-module(i2p_upnp_srv).

-moduledoc """
UPnP port-mapping service.

Discovers an Internet Gateway Device via SSDP, fetches its device description,
and installs (and periodically renews) port mappings for the router's NTCP2
(TCP) and SSU2 (UDP) listen ports, so an unpublished router behind NAT can
publish a reachable RouterAddress instead of relying on introducers alone.

Bounded and off by default, like transit and floodfill: a router must be able
to run with no UPnP traffic at all, and the switch is hot. Instrumentation
lands with the behaviour: mapping discovered, renewed, lost, refused.

Config: app env `i2per` -> `upnp` (boolean, default false), `upnp_name`
(string, default "I2Pd").
""".

-behaviour(gen_server).

-export([start_link/0, stop/0, enabled/0, status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SSDP_ADDR, {239, 255, 255, 250}).
-define(SSDP_PORT, 1900).
-define(DISCOVER_TIMEOUT_MS, 5000).
-define(RENEW_INTERVAL_MS, 20 * 60 * 1000).
-define(MAX_RAW, 65536).

-record(state, {
    enabled = false :: boolean(),
    name = "I2Pd" :: string(),
    socket = undefined :: gen_udp:socket() | undefined,
    locations = [] :: [binary()],
    control_url = undefined :: string() | undefined,
    service_type = "urn:schemas-upnp-org:service:WANIPConnection:1" :: string(),
    internal_ip = undefined :: string() | undefined,
    ports = [] :: [{pos_integer(), string()}],
    timer = undefined :: reference() | undefined,
    discovered = false :: boolean()
}).

-spec enabled() -> boolean().
enabled() ->
    case application:get_env(i2per, upnp) of
        {ok, true} -> true;
        _ -> false
    end.

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec stop() -> ok.
stop() ->
    case whereis(?MODULE) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

-spec status() -> map().
status() ->
    case whereis(?MODULE) of
        undefined -> #{enabled => enabled(), running => false};
        Pid -> gen_server:call(Pid, status)
    end.

-spec init([]) -> {ok, #state{}}.
init([]) ->
    _ = inets:start(),
    Name =
        case application:get_env(i2per, upnp_name) of
            {ok, V} when is_list(V) -> V;
            {ok, V} when is_binary(V) -> binary_to_list(V);
            _ -> "I2Pd"
        end,
    Ports = configured_ports(),
    St0 = #state{enabled = enabled(), name = Name, ports = Ports},
    case enabled() of
        true ->
            St1 = discover(St0),
            {ok, St1};
        false ->
            {ok, St0}
    end.

-spec handle_call(term(), gen_server:from(), #state{}) ->
    {reply, term(), #state{}}.
handle_call(status, _From, St) ->
    {reply,
        #{
            enabled => St#state.enabled,
            discovered => St#state.discovered,
            control_url => St#state.control_url
        },
        St};
handle_call(_Req, _From, St) ->
    {reply, ok, St}.

-spec handle_cast(term(), #state{}) -> {noreply, #state{}}.
handle_cast(_Msg, St) ->
    {noreply, St}.

-spec handle_info(term(), #state{}) -> {noreply, #state{}}.
handle_info({udp, _Sock, _IP, _Port, Bin}, St) ->
    Locs = parse_locations(Bin),
    St2 = St#state{locations = St#state.locations ++ Locs},
    {noreply, St2};
handle_info(discover_timeout, St) ->
    _ =
        case St#state.socket of
            undefined -> ok;
            Sock -> gen_udp:close(Sock)
        end,
    St2 = St#state{socket = undefined},
    St3 =
        case St2#state.locations of
            [] ->
                catch i2p_counters:add(upnp_mapping_lost, 1),
                catch i2p_events:notify({upnp_mapping_lost, no_gateway}),
                St2;
            _ ->
                fetch_and_map(St2)
        end,
    TRef = erlang:send_after(?RENEW_INTERVAL_MS, self(), renew),
    {noreply, St3#state{timer = TRef}};
handle_info(renew, St) ->
    case St#state.control_url of
        undefined ->
            %% The first discovery found no gateway, or a later mapping lost it.
            %% Re-run discovery; its timeout schedules the next renewal, so a
            %% router that boots before the gateway is up keeps trying.
            {noreply, discover(St#state{timer = undefined})};
        _ ->
            St2 = do_mapping(St),
            TRef = erlang:send_after(?RENEW_INTERVAL_MS, self(), renew),
            {noreply, St2#state{timer = TRef}}
    end;
handle_info(_Info, St) ->
    {noreply, St}.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, St) ->
    case St#state.control_url of
        undefined -> ok;
        _ -> delete_mappings(St)
    end,
    case St#state.socket of
        undefined -> ok;
        Sock -> gen_udp:close(Sock)
    end,
    _ =
        case St#state.timer of
            undefined -> ok;
            TRef -> erlang:cancel_timer(TRef)
        end,
    ok.

-spec code_change(term(), #state{}, term()) -> {ok, #state{}}.
code_change(_Old, St, _Extra) ->
    {ok, St}.

%% ---- internal ----

configured_ports() ->
    Ports = [],
    Ports1 =
        case application:get_env(i2per, port) of
            {ok, P} when is_integer(P), P > 0 -> [{P, "TCP"} | Ports];
            _ -> Ports
        end,
    case application:get_env(i2per, ssu2_port) of
        {ok, P2} when is_integer(P2), P2 > 0 -> [{P2, "UDP"} | Ports1];
        _ -> Ports1
    end.

discover(St) ->
    case gen_udp:open(0, [binary, {active, true}]) of
        {ok, Sock} ->
            Msg = ssdp_search(),
            _ = gen_udp:send(Sock, ?SSDP_ADDR, ?SSDP_PORT, Msg),
            erlang:send_after(?DISCOVER_TIMEOUT_MS, self(), discover_timeout),
            St#state{socket = Sock};
        {error, _} ->
            catch i2p_counters:add(upnp_mapping_refused, 1),
            TRef = erlang:send_after(?RENEW_INTERVAL_MS, self(), renew),
            St#state{timer = TRef}
    end.

ssdp_search() ->
    iolist_to_binary([
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 3\r\n",
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
        "\r\n"
    ]).

parse_locations(Bin) ->
    case
        re:run(Bin, "[Ll]ocation:[ \t]*([^ \t\r\n]+)", [
            global, {capture, all_but_first, binary}
        ])
    of
        {match, Ms} -> [L || [L] <- Ms];
        nomatch -> []
    end.

fetch_and_map(St) ->
    Locs = St#state.locations,
    case Locs of
        [] ->
            St;
        [Loc | _] ->
            case fetch_description(Loc) of
                {ok, ControlUrl, SvcType} ->
                    catch i2p_counters:add(upnp_mapping_discovered, 1),
                    catch i2p_events:notify({upnp_mapping_discovered, Loc}),
                    St2 = St#state{
                        control_url = ControlUrl, service_type = SvcType, discovered = true
                    },
                    do_mapping(St2);
                {error, Reason} ->
                    catch i2p_counters:add(upnp_mapping_refused, 1),
                    catch i2p_events:notify({upnp_mapping_lost, Reason}),
                    St
            end
    end.

fetch_description(Location) ->
    %% `httpc` and `uri_string` both take a URL as a string here, so the binary
    %% captured from SSDP is converted at this one boundary.
    Url = binary_to_list(Location),
    case httpc:request(get, {Url, []}, [{timeout, 5000}], []) of
        {ok, {{_, 200, _}, _Headers, Body}} ->
            parse_control_url(Url, Body);
        {ok, {{_, Code, _}, _, _}} ->
            {error, {http_status, Code}};
        {error, Reason} ->
            {error, Reason}
    end.

parse_control_url(Base, Body) ->
    %% Walk the service blocks instead of the first controlURL in the document:
    %% an InternetGatewayDevice description lists several services, and the first
    %% controlURL is often WANCommonInterfaceConfig, not the connection service.
    case
        re:run(Body, "<service>(.*?)</service>", [global, dotall, {capture, all_but_first, list}])
    of
        {match, Blocks} ->
            pick_wan_service(Base, Blocks);
        nomatch ->
            {error, no_wan_service}
    end.

pick_wan_service(_Base, []) ->
    {error, no_wan_service};
pick_wan_service(Base, [Block | Rest]) ->
    case
        re:run(
            Block,
            "urn:schemas-upnp-org:service:(WANIPConnection|WANPPPConnection):([0-9]+)",
            [{capture, all_but_first, list}]
        )
    of
        {match, [Svc, Ver]} ->
            case
                re:run(Block, "<controlURL>([^<]+)</controlURL>", [{capture, all_but_first, list}])
            of
                {match, [[CU]]} ->
                    {ok, resolve_url(Base, string:trim(CU)),
                        "urn:schemas-upnp-org:service:" ++ Svc ++ ":" ++ Ver};
                nomatch ->
                    {error, no_control_url}
            end;
        nomatch ->
            pick_wan_service(Base, Rest)
    end.

resolve_url(Base, Rel) ->
    case uri_string:parse(Rel) of
        #{scheme := _} ->
            Rel;
        _ ->
            try uri_string:resolve(Rel, Base) of
                Resolved when is_binary(Resolved) -> binary_to_list(Resolved);
                Resolved when is_list(Resolved) -> Resolved
            catch
                _:_ -> Rel
            end
    end.

do_mapping(St) ->
    CU = St#state.control_url,
    ST = St#state.service_type,
    IP =
        case St#state.internal_ip of
            undefined ->
                case internal_ip() of
                    {ok, S} -> S;
                    _ -> "127.0.0.1"
                end;
            V ->
                V
        end,
    St2 = St#state{internal_ip = IP},
    lists:foreach(
        fun({Port, Proto}) ->
            Body = add_port_mapping_body(Port, Proto, IP, St#state.name, ST),
            Action = ST ++ "#AddPortMapping",
            case soap_request(CU, Action, Body) of
                {ok, _} ->
                    catch i2p_counters:add(upnp_mapping_renewed, 1),
                    catch i2p_events:notify({upnp_mapping_renewed, Port, Proto});
                {error, Reason} ->
                    catch i2p_counters:add(upnp_mapping_refused, 1),
                    catch i2p_events:notify({upnp_mapping_refused, Port, Proto, Reason})
            end
        end,
        St#state.ports
    ),
    St2.

add_port_mapping_body(Port, Proto, IP, Name, ServiceType) ->
    iolist_to_binary([
        "<?xml version=\"1.0\"?>",
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">",
        "<s:Body>",
        "<u:AddPortMapping xmlns:u=\"",
        ServiceType,
        "\">",
        "<NewRemoteHost></NewRemoteHost>",
        "<NewExternalPort>",
        integer_to_list(Port),
        "</NewExternalPort>",
        "<NewProtocol>",
        Proto,
        "</NewProtocol>",
        "<NewInternalPort>",
        integer_to_list(Port),
        "</NewInternalPort>",
        "<NewInternalClient>",
        IP,
        "</NewInternalClient>",
        "<NewEnabled>1</NewEnabled>",
        "<NewPortMappingDescription>",
        Name,
        "</NewPortMappingDescription>",
        "<NewLeaseDuration>0</NewLeaseDuration>",
        "</u:AddPortMapping>",
        "</s:Body>",
        "</s:Envelope>"
    ]).

soap_request(Url, Action, Body) ->
    Headers = [
        {"SOAPAction", "\"" ++ Action ++ "\""},
        {"Content-Type", "text/xml; charset=\"utf-8\""}
    ],
    case httpc:request(post, {Url, Headers, "text/xml", Body}, [{timeout, 5000}], []) of
        {ok, {{_, Code, _}, _, _Resp}} when Code >= 200, Code < 300 ->
            {ok, Code};
        {ok, {{_, Code, _}, _, Resp}} ->
            {error, {http_status, Code, Resp}};
        {error, Reason} ->
            {error, Reason}
    end.

delete_mappings(St) ->
    CU = St#state.control_url,
    ST = St#state.service_type,
    _ = [
        begin
            Body = delete_port_mapping_body(Port, Proto, ST),
            Action = ST ++ "#DeletePortMapping",
            _ = soap_request(CU, Action, Body)
        end
     || {Port, Proto} <- St#state.ports
    ],
    ok.

delete_port_mapping_body(Port, Proto, ServiceType) ->
    iolist_to_binary([
        "<?xml version=\"1.0\"?>",
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">",
        "<s:Body>",
        "<u:DeletePortMapping xmlns:u=\"",
        ServiceType,
        "\">",
        "<NewRemoteHost></NewRemoteHost>",
        "<NewExternalPort>",
        integer_to_list(Port),
        "</NewExternalPort>",
        "<NewProtocol>",
        Proto,
        "</NewProtocol>",
        "</u:DeletePortMapping>",
        "</s:Body>",
        "</s:Envelope>"
    ]).

internal_ip() ->
    case inet:getifaddrs() of
        {ok, Ifs} ->
            find_ip(Ifs);
        _ ->
            error
    end.

find_ip([]) ->
    error;
find_ip([{_Name, Opts} | Rest]) ->
    case lists:keyfind(addr, 1, Opts) of
        {addr, {A, B, C, D}} when A =/= 127 ->
            {ok, lists:flatten(io_lib:format("~b.~b.~b.~b", [A, B, C, D]))};
        _ ->
            find_ip(Rest)
    end.
