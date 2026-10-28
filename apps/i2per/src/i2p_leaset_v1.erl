-module(i2p_leaset_v1).

-moduledoc """
LeaseSet (DatabaseStore `store_type` 1): the original, deprecated I2P
LeaseSet.

A v1 LeaseSet advertises a Destination's inbound tunnels: the Destination
identity, an ElGamal encryption key, a (revocation) signing key, up to 16
leases (each `gateway ‖ tunnelID ‖ endDate`, with an 8-byte millisecond
`end_date`) and an Ed25519 signature by the Destination's signing key.

i2per only **receives, stores and serves** v1 LeaseSets. It never publishes
one: its identities are X25519 + Ed25519, and a v1 encryption key is
ElGamal, so publishing would require a legacy identity i2per does not have.

Wire format (`destination ‖ encryption_key ‖ signing_key ‖ num ‖ leases ‖
signature`):

```
destination    KeysAndCert (>= 387 bytes, X25519 + Ed25519 here)
encryption_key 256 bytes (ElGamal, opaque to i2per)
signing_key    32 bytes for an Ed25519 destination (the destination's
               signing-key length)
num            1 byte, number of leases (0..16)
lease          44 bytes each: gateway(32) ‖ tunnelID(4 BE) ‖ endDate(8 BE, ms)
signature      Ed25519, 64 bytes, over destination ‖ encryption_key ‖
               signing_key ‖ num ‖ leases
```

The DatabaseStore `store_type` byte (1) is external to this content and is
placed by `m:i2p_i2np` in the message body, exactly as for LeaseSet2.

## Usage

```erlang
{ok, LS} = i2p_leaset_v1:decode(Bin),   %% Bin without store-type byte
Bin = i2p_leaset_v1:to_binary(LS),
Key = i2p_leaset_v1:hash(LS),            %% Destination hash
ok = i2p_leaset_v1:valid(LS, NowSec).
```
""".
-export([
    decode/1,
    to_binary/1,
    identity/1,
    hash/1,
    store_type/0,
    valid/2,
    leases/1,
    encryption_key/1,
    signing_key/1
]).
-export_type([lease_set/0, lease/0]).

-define(STORE_TYPE, 1).
-define(ENC_KEY_LEN, 256).
-define(LEASE_SIZE, 44).
-define(MAX_LEASES, 16).
-define(SIG_LEN, 64).

-opaque lease_set() :: #{
    binary := binary(),
    identity := i2p_keys:identity(),
    encryption_key := binary(),
    signing_key := binary(),
    leases := [lease()],
    signature := i2p_crypto:ed25519_signature()
}.
-type lease() :: #{
    gateway := i2p_crypto:hash(),
    tunnel_id := 0..16#FFFFFFFF,
    end_date := non_neg_integer()
}.

-doc "DatabaseStore `store_type` 1 — a v1 LeaseSet.".
-spec store_type() -> 1.
store_type() -> ?STORE_TYPE.

-doc "Parse and verify a v1 LeaseSet. Input: full signed content bytes without the store-type byte.".
-spec decode(binary()) -> {ok, lease_set()} | {error, term()}.
decode(Bin) when is_binary(Bin) ->
    Size = byte_size(Bin),
    %% Destination is at least 387 bytes (384 + 3 cert). Read its cert length.
    if
        Size < 387 ->
            {error, too_short};
        true ->
            <<_:384/binary, _:8, CertLen:16/big, _/binary>> = Bin,
            DestSize = 384 + 3 + CertLen,
            case Size >= DestSize + ?ENC_KEY_LEN + 1 + ?SIG_LEN of
                false ->
                    {error, too_short};
                true ->
                    DestBin = binary:part(Bin, 0, DestSize),
                    case i2p_keys:parse(DestBin) of
                        {ok, Identity} ->
                            parse_body(Identity, DestBin, Bin, DestSize);
                        {error, Reason} ->
                            {error, {bad_identity, Reason}}
                    end
            end
    end;
decode(_) ->
    {error, badarg}.

parse_body(Identity, _DestBin, Bin, DestSize) ->
    SignKeyLen = byte_size(i2p_keys:signing_key(Identity)),
    Rest = binary:part(Bin, DestSize, byte_size(Bin) - DestSize),
    case Rest of
        <<EncKey:?ENC_KEY_LEN/binary, SignKey:SignKeyLen/binary, Num:8, Rest2/binary>> when
            Num =< ?MAX_LEASES
        ->
            LeaseBytes = Num * ?LEASE_SIZE,
            case Rest2 of
                <<LeasesBin:LeaseBytes/binary, Sig:?SIG_LEN/binary>> ->
                    case parse_leases(LeasesBin, Num) of
                        {ok, Leases, _} ->
                            %% verify signature over destination..leases
                            SignedData = binary:part(Bin, 0, byte_size(Bin) - ?SIG_LEN),
                            SignPub = i2p_keys:signing_key(Identity),
                            case i2p_crypto:ed25519_verify(SignedData, Sig, SignPub) of
                                true ->
                                    {ok, #{
                                        binary => Bin,
                                        identity => Identity,
                                        encryption_key => EncKey,
                                        signing_key => SignKey,
                                        leases => Leases,
                                        signature => Sig
                                    }};
                                false ->
                                    {error, bad_signature}
                            end;
                        error ->
                            {error, malformed}
                    end;
                _ ->
                    {error, malformed}
            end;
        _ ->
            {error, malformed}
    end.

parse_leases(Bin, 0) ->
    {ok, [], Bin};
parse_leases(<<Gateway:32/binary, TunnelID:32/big, EndDate:64/big, Rest/binary>>, N) when N > 0 ->
    case parse_leases(Rest, N - 1) of
        {ok, Leases, Rest2} ->
            {ok, [#{gateway => Gateway, tunnel_id => TunnelID, end_date => EndDate} | Leases],
                Rest2};
        error ->
            error
    end;
parse_leases(_, _) ->
    error.

-doc "Return the full signed content bytes.".
-spec to_binary(lease_set()) -> binary().
to_binary(#{binary := Bin}) -> Bin.

-doc "Return the Destination identity.".
-spec identity(lease_set()) -> i2p_keys:identity().
identity(#{identity := Id}) -> Id.

-doc "Return the Destination hash (NetDb key).".
-spec hash(lease_set()) -> i2p_crypto:hash().
hash(#{identity := Id}) -> i2p_keys:hash(Id).

-doc "Return the leases.".
-spec leases(lease_set()) -> [lease()].
leases(#{leases := L}) -> L.

-doc "Return the 256-byte ElGamal encryption key.".
-spec encryption_key(lease_set()) -> binary().
encryption_key(#{encryption_key := K}) -> K.

-doc "Return the revocation signing key.".
-spec signing_key(lease_set()) -> binary().
signing_key(#{signing_key := K}) -> K.

-doc """
Check expiry. A v1 LeaseSet has no published timestamp; it is expired when
all of its leases have ended (or when it has no leases).
Input: `LS`; `NowSec` — wall-clock seconds since epoch.
""".
-spec valid(lease_set(), non_neg_integer()) -> ok | {error, expired}.
valid(#{leases := []}, _NowSec) ->
    {error, expired};
valid(#{leases := Leases}, NowSec) when is_integer(NowSec), NowSec >= 0 ->
    NowMs = NowSec * 1000,
    MaxEnd = lists:max([maps:get(end_date, L) || L <- Leases]),
    %% Cap how far into the future a LeaseSet's end_date may reach, so a
    %% peer cannot store one that never expires.
    MaxFutureMs = NowMs + 24 * 60 * 60 * 1000,
    if
        NowMs > MaxEnd -> {error, expired};
        MaxEnd > MaxFutureMs -> {error, expired};
        true -> ok
    end;
valid(_LS, _NowSec) ->
    error(badarg).
