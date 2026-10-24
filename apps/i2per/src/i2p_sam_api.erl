-module(i2p_sam_api).

-moduledoc """
Public, versioned Erlang API for companion applications.

This is the socket-free entry point that Tier 1 presentation apps
(`i2per_proxy`, `i2per_tun`, ...) use to talk to the core over the Erlang
network, per ADR 0001 and ADR 0004 (E1CHFWF). It replaces the SAM-over-TCP
client path those apps used to duplicate: instead of opening a TCP socket to
port 7656 and driving the SAM line protocol, a companion app calls these
functions (locally or via `erpc`) and gets back Erlang terms.

The API is versioned: `f:version/0` reports the contract version a caller is
compiled against, so a companion app can detect a core that is older or newer
than itself before it relies on a shape. Additions are additive within a
version; a breaking change bumps the number.

## Usage

```erlang
Vsn = i2p_sam_api:version(),
{ok, DestB64} = i2p_sam_api:naming_lookup(<<"peer.i2p">>),
{ok, Dest} = i2p_sam_api:create_destination().
```
""".

-export([
    version/0,
    naming_lookup/1,
    create_destination/0,
    create_destination/1,
    create_session/1,
    create_session/0,
    stream_connect/3,
    stream_send/2,
    stream_close/1,
    session_dest_b64/1,
    raw_send/2
]).

%% The specs are contracts: these may grow beyond today's literal success
%% typing, so narrowing them would make them hand-maintained copies.
-dialyzer(
    {no_underspecs, [
        version/0,
        create_destination/0,
        create_destination/1,
        create_session/0,
        create_session/1,
        stream_connect/3,
        stream_send/2,
        stream_close/1,
        session_dest_b64/1,
        raw_send/2
    ]}
).

-doc "Contract version of this API.".
-spec version() -> pos_integer().
version() -> 1.

-doc """
Resolve a name to a destination base64 string.

`Name` may be a `.b32.i2p` address, a hostname known to the local
address book, or a base64 destination. Runs on the core node; a companion
app calls it via `erpc:call(RouterNode, i2p_sam_api, naming_lookup, [Name])`.

Output: `{ok, DestB64}` or `{error, Reason}`.
""".
-spec naming_lookup(binary() | string()) -> {ok, binary()} | {error, term()}.
naming_lookup(Name) when is_list(Name) ->
    naming_lookup(list_to_binary(Name));
naming_lookup(Name) when is_binary(Name) ->
    case i2p_addressbook:resolve(Name) of
        {ok, DestB64} ->
            {ok, DestB64};
        {error, Reason} ->
            %% Fall back to treating the input as an already-encoded
            %% destination: validate it parses, then echo it back.
            case i2p_keys:from_b64(Name) of
                {ok, _Identity} ->
                    {ok, Name};
                {error, _} ->
                    {error, Reason}
            end
    end.

-doc """
Generate a fresh destination (identity + private keys) for a companion app.

Output: a map with `identity`, `crypto_priv`, `sign_priv`, and the
base64-encoded destination `dest_b64`. The companion app owns these keys;
the core never stores them, matching how SAM's `DEST GENERATE` behaves.
""".
-spec create_destination() -> map().
create_destination() ->
    create_destination(#{}).

-doc """
Generate a fresh destination, honoring `sig_type` in `Opts` (default 7,
Ed25519, the only type this router supports).
""".
-spec create_destination(map()) -> map().
create_destination(_Opts) ->
    #{identity := Identity, crypto_priv := CPriv, sign_priv := SPriv} =
        i2p_keys:generate_with_privkeys(),
    DestB64 = i2p_keys:to_b64(Identity),
    #{
        identity => Identity,
        crypto_priv => CPriv,
        sign_priv => SPriv,
        dest_b64 => DestB64
    }.

-doc """
Create a headless client session.

`Opts` may carry `tunnel_lengths` (a `t:tunnel_lengths()` map). Returns
`{ok, Pid, DestB64}` where `Pid` is the session process and `DestB64`
is this session's destination, or `{error, Reason}`.
""".
-spec create_session() -> {ok, pid(), binary()} | {error, term()}.
create_session() ->
    create_session(#{}).

-spec create_session(map()) -> {ok, pid(), binary()} | {error, term()}.
create_session(Opts) ->
    Gen = i2p_keys:generate_with_privkeys(),
    #{identity := Identity, crypto_priv := CPriv, sign_priv := SPriv} = Gen,
    Args = #{
        identity => Identity,
        crypto_priv => CPriv,
        sign_priv => SPriv,
        tunnel_lengths => maps:get(tunnel_lengths, Opts, #{})
    },
    case i2p_client_session:start_link(Args) of
        {ok, Pid} ->
            {ok, Pid, i2p_keys:to_b64(Identity)};
        {error, Reason} ->
            {error, Reason}
    end.

-doc "Destination base64 of a session created by `f:create_session/0-1`.".
-spec session_dest_b64(pid()) -> binary().
session_dest_b64(Pid) ->
    gen_server:call(Pid, dest_b64).

-doc """
Open a streaming connection from `Session` to `Target`.

`Target` is a base64 destination, a `.b32.i2p` address, or a hostname
resolvable by the address book. `Owner` receives `{stream_data, Conn, Bytes}`,
`{stream_established, Conn, PeerHash}`, `{stream_closed, Conn}` and
`{stream_reset, Conn}` messages. Returns `{ok, ConnPid}` or
`{error, Reason}`.
""".
-spec stream_connect(pid() | map(), binary() | string() | map(), pid()) ->
    {ok, pid()} | {error, term()}.
stream_connect(Session, Target, Owner) when is_pid(Session) ->
    gen_server:call(Session, {stream_connect, Target, Owner}, 15000);
stream_connect(_SessionMap, Target, Owner) ->
    %% Allow callers that kept the create_destination map to connect without
    %% a running session process: spawn an ephemeral session.
    case create_session(#{}) of
        {ok, Pid, _} -> stream_connect(Pid, Target, Owner);
        {error, R} -> {error, R}
    end.

-doc "Send bytes on a connection returned by `f:stream_connect/3`.".
-spec stream_send(pid(), binary() | iolist()) -> ok.
stream_send(Conn, Data) ->
    i2p_stream_conn:send(Conn, iolist_to_binary(Data)).

-doc "Close a streaming connection.".
-spec stream_close(pid()) -> ok.
stream_close(Conn) ->
    i2p_stream_conn:close(Conn).

-doc """
Send an anonymous (raw) datagram to `Target`.

`Target` is a base64 destination, a `.b32.i2p` address, or a hostname
resolvable by the address book. `Payload` is sent as-is, garlic-wrapped to
the target. Returns `ok` or `{error, Reason}`.
""".
-spec raw_send(binary() | string(), binary() | iolist()) -> ok | {error, term()}.
raw_send(Target, Payload) when is_list(Target) ->
    raw_send(list_to_binary(Target), Payload);
raw_send(Target, Payload) ->
    Bin = iolist_to_binary(Payload),
    case resolve_raw_target(Target) of
        {ok, Route} ->
            i2p_client:send_wire(Route, Bin),
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

%% resolve_raw_target/1 — resolve a name/destination to a route, mirroring
%% SAM's RAW SEND target resolution.
resolve_raw_target(Target) ->
    case i2p_keys:from_b64(Target) of
        {ok, Identity} ->
            i2p_client:route_to_dest(i2p_keys:to_binary(Identity));
        {error, _} ->
            case i2p_addressbook:resolve(Target) of
                {ok, DestB64} ->
                    case i2p_keys:from_b64(DestB64) of
                        {ok, Identity} ->
                            i2p_client:route_to_dest(i2p_keys:to_binary(Identity));
                        {error, _} ->
                            {error, bad_destination}
                    end;
                {error, _} ->
                    {error, not_found}
            end
    end.
