-module(i2p_client_session).

-moduledoc """
Headless client session for companion applications (E1CHFWF).

A socket-free counterpart to `m:i2p_sam_session`: it owns a destination
(identity + keys) and publishes its LeaseSet, but never touches a TCP
socket. Inbound/outbound byte flow happens through `m:i2p_stream_conn`
processes that report `{stream_data, Conn, Bytes}` to their owner, so a
companion app can read and write streams directly.

This is the client side only: no `STREAM ACCEPT`/`FORWARD`, no datagram
sessions. Companion apps that need to accept inbound streams will get
those in a later slice.
""".

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-export_type([session/0]).

-type session() :: pid().

-doc "Start a headless client session.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(#{identity := _} = Args) ->
    gen_server:start_link(?MODULE, Args, []).

init(#{identity := Identity, crypto_priv := CPriv, sign_priv := SPriv} = Args) ->
    DestHash = i2p_keys:hash(Identity),
    DestBin = i2p_keys:to_binary(Identity),
    DestB64 = i2p_keys:to_b64(Identity),
    Lengths = maps:get(tunnel_lengths, Args, #{}),
    %% Publish a LeaseSet so remote peers can reach us, mirroring SAM's
    %% SESSION CREATE. Best-effort: a router that is not fully booted
    %% (hermetic unit tests) simply leaves the publish pending.
    catch i2p_tunnel_srv:publish_lease_set(Identity, SPriv, in_len(Lengths)),
    catch register_lengths(Lengths, self()),
    {ok, #{
        identity => Identity,
        crypto_priv => CPriv,
        sign_priv => SPriv,
        dest_b64 => DestB64,
        dest_hash => DestHash,
        dest_bin => DestBin,
        tunnel_lengths => Lengths
    }}.

handle_call({stream_connect, Target, Owner}, _From, State) ->
    Result = do_stream_connect(Target, Owner, State),
    {reply, Result, State};
handle_call(dest_b64, _From, #{dest_b64 := B64} = State) ->
    {reply, B64, State};
handle_call(_Req, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%% ---- helpers ----

in_len(Lengths) ->
    maps:get(in_len, Lengths, 3).

register_lengths(Lengths, _Self) when map_size(Lengths) =:= 0 ->
    ok;
register_lengths(Lengths, Self) ->
    InLen = maps:get(in_len, Lengths, 3),
    OutLen = maps:get(out_len, Lengths, 3),
    catch i2p_tunnel_srv:set_lengths(Self, InLen, OutLen),
    ok.

do_stream_connect(Target, Owner, State) ->
    case resolve_target(Target) of
        {error, Reason} ->
            {error, Reason};
        {ok, _TargetB64, TargetBin, TargetHash} ->
            case i2p_client:route_to_dest(TargetBin) of
                error ->
                    {error, no_route};
                {ok, Route} ->
                    ConnOpts = #{
                        role => connect,
                        owner => Owner,
                        send_fn => fun(Wire) -> i2p_client:send_wire(Route, Wire) end,
                        local_seed => maps:get(sign_priv, State),
                        local_dest_bin => maps:get(dest_bin, State),
                        local_dest_hash => maps:get(dest_hash, State),
                        remote_dest_bin => TargetBin,
                        remote_dest_hash => TargetHash
                    },
                    case i2p_stream_conn:start_link(ConnOpts) of
                        {ok, ConnPid} -> {ok, ConnPid}
                    end
            end
    end.

resolve_target(Target) when is_binary(Target) ->
    case i2p_keys:from_b64(Target) of
        {ok, Identity} ->
            {ok, Target, i2p_keys:to_binary(Identity), i2p_keys:hash(Identity)};
        {error, _} ->
            %% hostname / .b32: try address book, then naming
            case i2p_addressbook:resolve(Target) of
                {ok, DestB64} ->
                    case i2p_keys:from_b64(DestB64) of
                        {ok, Id} ->
                            {ok, DestB64, i2p_keys:to_binary(Id), i2p_keys:hash(Id)};
                        {error, _} ->
                            {error, bad_destination}
                    end;
                {error, _} ->
                    {error, not_found}
            end
    end;
resolve_target(Target) when is_list(Target) ->
    resolve_target(list_to_binary(Target)).
