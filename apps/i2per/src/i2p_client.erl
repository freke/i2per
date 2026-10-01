-module(i2p_client).

-moduledoc """
Client-side tunnel usage: lease selection and end-to-end garlic payloads.

Pure helpers shared by the SAM bridge and the tunnel manager's client paths.
A sender resolves a remote destination to its freshest unexpired lease
(`f:pick_lease/1`), wraps raw stream bytes into a destination-addressed
garlic message (`f:wrap_payload/2`), and injects the result into one of its
outbound tunnels via `m:i2p_tunnel_srv:send_via_outbound/3` naming the
lease's gateway and tunnel ID. The receiver opens the arriving garlic with
the destination's ECIES private key (`f:unwrap_payload/2`) and feeds the
bytes to the owning session.

## Usage

```erlang
{ok, {Gateway, TunnelID}} = i2p_client:pick_lease(LS),
{ok, Body} = i2p_client:wrap_payload(DestPub, <<"hello">>),
StdMsg = i2p_i2np:encode_std(#{type => 11, msg_id => ID,
                               expiration_ms => 60000, body => Body}),
ok = i2p_tunnel_srv:send_via_outbound(TunID, {tunnel, Gateway, TunnelID}, StdMsg).
```
""".
-export([
    pick_lease/1,
    pick_lease/2,
    wrap_payload/2,
    unwrap_payload/2,
    route_to_dest/1,
    send_wire/2
]).

-export_type([route/0]).

-doc """
A pinned end-to-end stream route: one of our outbound tunnels plus the
remote destination's freshest lease and identity fields. Built by
`f:route_to_dest/1`, consumed by `f:send_wire/2`.
""".
-type route() :: #{
    out_tid := 0..16#FFFFFFFF,
    gw := i2p_crypto:hash(),
    tid := 0..16#FFFFFFFF,
    dest_pub := i2p_crypto:x25519_public_key(),
    dest_bin => binary(),
    dest_hash => i2p_crypto:hash()
}.

-doc """
The lease a sender picked: the gateway router hash and the inbound tunnel
ID to address the payload to.
""".
-type selected_lease() :: {i2p_crypto:hash(), 0..16#FFFFFFFF}.

%% I2NP Data message type: the payload carrier inside the end-to-end clove.
-define(DATA_TYPE, 31).
%% Clove lifetime in seconds from creation.
-define(CLOVE_LIFETIME_S, 60).

-doc """
Pick the freshest unexpired lease of a LeaseSet, at the current wall clock.

Output: `{ok, SelectedLease}` or `error` when every lease has expired.
""".
-spec pick_lease(i2p_leaset:lease_set()) -> {ok, selected_lease()} | error.
pick_lease(LS) ->
    pick_lease(LS, erlang:system_time(millisecond)).

%% The I2P date fields on the wire are 4-byte milliseconds (see
%% `m:i2p_leaset`), so expiry uses serial-number arithmetic modulo 2^32:
%% a lease is fresh when its end_date lands in the first half of the
%% window after now.
-define(DATE_MASK, 16#FFFFFFFF).
-define(DATE_HALF_WINDOW, 16#80000000).

-doc """
Pick the freshest unexpired lease of a LeaseSet against a fixed clock.

Input: `LS` — the decoded LeaseSet; `NowMs` — the reference time in ms.
Output: `{ok, SelectedLease}` or `error` when every lease has expired.
""".
-spec pick_lease(i2p_leaset:lease_set(), non_neg_integer()) ->
    {ok, selected_lease()} | error.
pick_lease(LS, NowMs) ->
    Fresh =
        [
            L
         || L <- i2p_leaset:leases(LS),
            delta_ms(maps:get(end_date, L), NowMs) > 0,
            delta_ms(maps:get(end_date, L), NowMs) < ?DATE_HALF_WINDOW
        ],
    case Fresh of
        [] ->
            error;
        _ ->
            %% Freshest lease last after ascending end-date sort
            Sorted = lists:sort([{maps:get(end_date, L), L} || L <- Fresh]),
            {_MaxEnd, Best} = lists:last(Sorted),
            {ok, {maps:get(gateway, Best), maps:get(tunnel_id, Best)}}
    end.

delta_ms(EndDate, NowMs) ->
    (EndDate - NowMs) band ?DATE_MASK.

-doc """
Wrap raw stream payload for a remote destination.

Builds one local-delivery clove carrying an I2NP Data message with the raw
bytes, Noise-N wrapped to the destination's ECIES static key — the same
one-shot format as router-directed garlic, addressed to a client identity.

Input: `DestCryptoPub` — the remote destination's X25519 public key;
`Payload` — the raw stream bytes.
Output: `{ok, GarlicBody}` — the garlic I2NP body ready to send as a
type-11 standard-header message through an outbound tunnel.
""".
-spec wrap_payload(i2p_crypto:x25519_public_key(), binary()) -> {ok, <<_:8, _:_*8>>}.
wrap_payload(DestCryptoPub, Payload) ->
    Clove = #{
        delivery => local,
        type => ?DATA_TYPE,
        msg_id => crypto:strong_rand_bytes(4),
        expiration => erlang:system_time(second) + ?CLOVE_LIFETIME_S,
        data => Payload
    },
    #{body := Body} = i2p_garlic:wrap_router([Clove], DestCryptoPub),
    {ok, Body}.

-doc """
Open an end-to-end garlic payload with a destination's ECIES private key.

Inverse of `f:wrap_payload/2`.

Input: `DestCryptoPriv` — the local destination's X25519 private key;
`GarlicBody` — the type-11 message body received out of an inbound tunnel.
Output: `{ok, Payload}` — the raw stream bytes; `error` when the message
was not addressed to this destination or is malformed.
""".
-spec unwrap_payload(i2p_crypto:x25519_private_key(), binary()) -> {ok, binary()} | error.
unwrap_payload(DestCryptoPriv, GarlicBody) ->
    case i2p_i2np:decode_garlic(GarlicBody) of
        {ok, #{data := Encrypted}} ->
            case i2p_garlic:unwrap_router(Encrypted, DestCryptoPriv) of
                {ok, Blocks} ->
                    case
                        [D || #{type := ?DATA_TYPE, data := D} <- i2p_garlic:extract_cloves(Blocks)]
                    of
                        [Payload] -> {ok, Payload};
                        _ -> error
                    end;
                error ->
                    error
            end;
        error ->
            error
    end.

-doc """
Resolve a return route to a remote destination.

Looks the LeaseSet up in the local NetDb first and falls back to the
tunnel-based remote lookup (`m:i2p_lookup_srv`), picks the freshest unexpired
lease and pins one of our outbound tunnels.

Input: `DestBin` — the 391-byte destination identity binary.
Output: `{ok, Route}` — see `t:route/0`; `error` when the destination does
not parse, its LeaseSet cannot be found, every lease expired, or no outbound
tunnel exists yet.
""".
-spec route_to_dest(binary()) -> {ok, route()} | error.
route_to_dest(DestBin) ->
    case i2p_keys:parse(DestBin) of
        {ok, Identity} -> lease_route(Identity, DestBin);
        {error, _Reason} -> error
    end.

-doc """
Transport for streaming connections: garlic-wrap ONE encoded streaming packet
for the route's destination and inject it into the pinned outbound tunnel
toward the lease. A vanished tunnel drops the packet; the connection's resend
machinery recovers it, so this returns `ok` either way and does not propagate.

**The drop is counted, not silent.** `m:i2p_stats` records it as
`client_messages_dropped_no_tunnel`, which is the companion to
`transit_frames_dropped_no_route`: that one is a frame this router could not
route, this is a message it routed and could not deliver. Not propagating is a
deliberate consequence of the resend guarantee above, not an absence of
reporting -- and the two are different, which is why the count exists.

Input: `Route` — a route from `f:route_to_dest/1`; `Wire` — one encoded
streaming packet.
Output: `ok`.
""".
-spec send_wire(route(), binary()) -> ok.
send_wire(#{out_tid := OutTid, gw := Gw, tid := Tid, dest_pub := DestPub}, Wire) ->
    {ok, GarlicBody} = wrap_payload(DestPub, Wire),
    StdMsg =
        i2p_i2np:encode_std(#{
            type => 11,
            msg_id => crypto:strong_rand_bytes(4),
            expiration_ms => 60000,
            body => GarlicBody
        }),
    case i2p_tunnel_srv:send_via_outbound(OutTid, {tunnel, Gw, Tid}, StdMsg) of
        ok -> ok;
        error -> i2p_stats:add(client_messages_dropped_no_tunnel, 1)
    end.

%% lease_route/2 — finish route resolution once the identity parses.
-spec lease_route(i2p_keys:identity(), binary()) -> {ok, route()} | error.
lease_route(Identity, DestBin) ->
    DestHash = i2p_keys:hash(Identity),
    LS =
        case i2p_netdb_srv:find_ls(DestHash) of
            {ok, Found} ->
                {ok, Found};
            not_found ->
                case i2p_lookup_srv:find_ls(DestHash) of
                    Result = {ok, _} -> Result;
                    {error, _} -> error
                end
        end,
    case LS of
        {ok, LeaseSet} ->
            case pick_lease(LeaseSet) of
                {ok, {Gw, Tid}} ->
                    case i2p_tunnel_srv:pick_outbound() of
                        {ok, OutTid, _Entry} ->
                            {ok, #{
                                out_tid => OutTid,
                                gw => Gw,
                                tid => Tid,
                                dest_pub => i2p_keys:public_key(Identity),
                                dest_bin => DestBin,
                                dest_hash => DestHash
                            }};
                        error ->
                            error
                    end;
                error ->
                    error
            end;
        error ->
            error
    end.
