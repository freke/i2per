-module(i2p_reseed).

-moduledoc """
Reseed client: bootstrap a fresh router's NetDb by fetching a signed SU3
reseed file over HTTPS and unpacking its RouterInfos.

Per the [reseed spec](https://geti2p.net/en/docs/spec/updates):

- The file lives at `<host>/i2pseeds.su3`; requests carry a `?netid=<n>` query
  so routers never cross network boundaries (the id comes from app env
  `i2per` → `net_id`, default 2).
- The SU3 container declares file type zip and content type reseed (`f:i2p_su3`);
  its zip holds top-level `routerInfo-<base64 hash>.dat` files.
- The signature is RSA-SHA512-4096. Trust anchors are local X.509 certificates
  selected by their subject CN, stored under `priv/certs/reseed/`, extended by
  whatever the caller adds. A file whose signer has no trusted certificate is
  refused before any signature work happens.

Fetching uses plain HTTPS with the OS trust store for the TLS layer; the SU3
signature is what actually authenticates the payload, so any working mirror
can serve it.

## Usage

```erlang
Trust = i2p_reseed:load_trust_store(),
{ok, Su3Bin} = i2p_reseed:fetch("https://reseed.i2p-projekt.de/"),
{ok, RIs} = i2p_reseed:process(Su3Bin, Trust),

%% Or the whole pipeline across the default host list:
{ok, RIs} = i2p_reseed:run().
```
""".

-export([
    default_hosts/0,
    seeds_url/1,
    fetch/1,
    process/2,
    run/0,
    run/1,
    run/2,
    load_trust_store/0
]).
-export_type([trust_store/0]).

-doc "Certificate subject CN → DER-encoded X.509 certificate.".
-type trust_store() :: #{binary() => binary()}.

-define(FILE_TYPE_ZIP, 0).
-define(CONTENT_TYPE_RESEED, 3).
-define(USER_AGENT, "i2per/" ++ version_string()).

-doc "The bundled reseed mirrors, tried in order by `f:run/0`.".
-spec default_hosts() -> [[1..255, ...], ...].
default_hosts() ->
    [
        "https://reseed.sahil.world/",
        "https://reseed2.i2p.net/",
        "https://reseed.diva.exchange/",
        "https://reseed-fr.i2pd.xyz/",
        "https://reseed.onion.im/",
        "https://i2pseed.creativecowpat.net:8443/",
        "https://reseed.i2pgit.org/",
        "https://reseed-pl.i2pd.xyz/",
        "https://www2.mk16.de/",
        "https://i2p.novg.net/",
        "https://reseed.stormycloud.org/",
        "https://i2p.diyarciftci.xyz/",
        "https://furland.horoshij.space/reseed/",
        "https://spiral.likogan.dev/"
    ].

-doc """
The full reseed-file URL for a host.

Input: `Host` — a base URL such as `"https://reseed.i2p-projekt.de/"`.
Output: `<Host>i2pseeds.su3?netid=<NetId>`, with `NetId` from app env
`i2per` → `net_id`, defaulting to 2.
""".
-spec seeds_url(string()) -> string().
seeds_url(Host) ->
    NetId =
        case application:get_env(i2per, net_id) of
            {ok, Id} -> integer_to_list(Id);
            undefined -> "2"
        end,
    Host ++ "i2pseeds.su3?netid=" ++ NetId.

-doc """
Fetch an SU3 reseed file.

Input: `Url` — the full URL (`f:seeds_url/1` builds it). Production hosts are
HTTPS; plain HTTP is accepted so tests can drive a localhost server.
Output: `{ok, Body}` or `{error, Reason}` (`{http_status, Code}` for non-200
responses, otherwise the transport reason).
""".
-spec fetch(string()) -> {ok, binary()} | {error, term()}.
fetch(Url) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    ProfileOpts = [
        {ssl, [
            {verify, verify_peer},
            {cacerts, public_key:cacerts_get()},
            {customize_hostname_check, [
                {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
            ]}
        ]},
        {autoredirect, true},
        {connect_timeout, 10_000},
        {timeout, 30_000}
    ],
    RequestOpts = [{body_format, binary}],
    case httpc:request(get, {Url, [{"user-agent", user_agent()}]}, ProfileOpts, RequestOpts) of
        {ok, {{_Version, 200, _Phrase}, _Headers, Body}} -> {ok, Body};
        {ok, {{_Version, Code, _Phrase}, _Headers, _Body}} -> {error, {http_status, Code}};
        {error, Reason} -> {error, Reason}
    end.

-doc """
Validate and unpack a fetched reseed file.

Input: `Su3Bin` — raw SU3 bytes; `TrustStore` — signer-ID → certificate map
(`f:load_trust_store/0`, optionally extended with extra anchors).
Output: `{ok, RouterInfos}` — every decodable `routerInfo-*.dat` entry in the
zip — or an error: `{unknown_signer, SignerId}`, `bad_signature`,
`no_router_infos`, or anything `m:i2p_su3` / `f:zip:unzip/2` can produce.

**An entry this module does not take is recorded, not dropped.** `reseed_failed`
says the bundle was refused as a whole; nothing said anything about the entries
this router quietly left out of one it accepted, which is the same silent loss
one level up. See `f:take_entries/1`.
""".
-spec process(binary(), trust_store()) -> {ok, [i2p_router_info:router_info()]} | {error, term()}.
process(Su3Bin, TrustStore) ->
    case i2p_su3:decode(Su3Bin) of
        {ok, Su3} when
            map_get(file_type, Su3) =:= ?FILE_TYPE_ZIP,
            map_get(content_type, Su3) =:= ?CONTENT_TYPE_RESEED
        ->
            verify_and_unpack(Su3, TrustStore);
        {ok, _Su3} ->
            {error, not_a_reseed_file};
        Error ->
            Error
    end.

-doc "Run the pipeline across `f:default_hosts/0`.".
-spec run() -> {ok, [i2p_router_info:router_info()]} | {error, term()}.
run() ->
    run(default_hosts()).

-doc """
Run the pipeline across `Hosts` in order, stopping at the first host that
yields RouterInfos.

Output: `{ok, RouterInfos}` or `{error, Reason}`, where `Reason` is the last
host's failure (`no_hosts` when the list is empty).
""".
-spec run([string()]) -> {ok, [i2p_router_info:router_info()]} | {error, term()}.
run(Hosts) ->
    run(Hosts, load_trust_store()).

-doc """
Run the pipeline across `Hosts` with an explicit trust store — the seam used
by tests and by callers that add anchors beyond the bundled set.

Output: `{ok, RouterInfos}` or `{error, Reason}`, where `Reason` is the last
host's failure (`no_hosts` when the list is empty).
""".
-spec run([string()], trust_store()) ->
    {ok, [i2p_router_info:router_info()]} | {error, term()}.
run(Hosts, TrustStore) ->
    try_hosts(Hosts, TrustStore, no_hosts).

-doc """
Load the bundled reseed trust anchors.

Output: signer ID → DER certificate, one entry per `.crt`/`.pem` file in
`priv/certs/reseed/`. The signer ID is the certificate subject CN, which is
the value carried in the SU3 signer-ID field.
""".
-spec load_trust_store() -> trust_store().
load_trust_store() ->
    Dir = filename:join(code:priv_dir(i2per), "certs/reseed"),
    case file:list_dir(Dir) of
        {ok, Files} ->
            maps:from_list([
                cert_entry(Dir, File)
             || File <- Files
            ]);
        {error, _enoent} ->
            #{}
    end.

%%%%%%% %%% Internal %%%%%%%

cert_entry(Dir, File) ->
    Path = filename:join(Dir, File),
    {ok, Pem} = file:read_file(Path),
    [{'Certificate', Der, _NotEncrypted} | _Rest] = public_key:pem_decode(Pem),
    {signer_id_of(Der), Der}.

signer_id_of(Der) ->
    {'Certificate', Tbs, _, _} = public_key:pkix_decode_cert(Der, plain),
    {rdnSequence, RdnSequence} = element(7, Tbs),
    Attributes = lists:append(RdnSequence),
    [Value | _] = [
        Value
     || {'AttributeTypeAndValue', Oid, Value} <- Attributes,
        Oid =:= {2, 5, 4, 3}
    ],
    cn_binary(Value).

cn_binary({_StringType, Value}) when is_binary(Value) ->
    Value;
cn_binary(Value) when is_binary(Value) ->
    Value;
cn_binary(Value) when is_list(Value) ->
    list_to_binary(Value).

user_agent() ->
    "i2per/" ++ version_string().

version_string() ->
    case application:get_key(i2per, vsn) of
        {ok, Vsn} when is_list(Vsn) -> Vsn;
        _ -> "0"
    end.

%% verify_and_unpack/2 — trust lookup by signer ID, then the spec's two extra
%% gates: the anchor certificate must still be within its validity window, and
%% the signature must check out.
verify_and_unpack(Su3, TrustStore) ->
    SignerId = maps:get(signer_id, Su3),
    verify_trusted(maps:find(SignerId, TrustStore), Su3, SignerId).

%% verify_trusted/3 — clause pair on the trust lookup: an unknown signer is
%% refused before any signature work happens.
verify_trusted({ok, CertDer}, Su3, SignerId) ->
    verify_fresh(i2p_su3:cert_valid_at(CertDer, calendar:universal_time()), Su3, CertDer, SignerId);
verify_trusted(error, _Su3, SignerId) ->
    {error, {unknown_signer, SignerId}}.

%% verify_fresh/4 — an expired anchor certificate fails the SU3 regardless of
%% its signature; a live one must actually sign the file.
verify_fresh(true, Su3, CertDer, _SignerId) ->
    case i2p_su3:verify(Su3, CertDer) of
        ok -> unzip_ris(maps:get(content, Su3));
        Error -> Error
    end;
verify_fresh(false, _Su3, _CertDer, SignerId) ->
    {error, {signer_cert_expired, SignerId}}.

unzip_ris(ZipBin) ->
    case zip:unzip(ZipBin, [memory]) of
        {ok, Entries} ->
            {Ris, Skipped} = take_entries(Entries),
            lists:foreach(fun report_skipped/1, Skipped),
            case Ris of
                [] -> {error, no_router_infos};
                _ -> {ok, Ris}
            end;
        {error, _not_a_zip} ->
            {error, no_router_infos}
    end.

%% Every entry, sorted into the RouterInfos this module can use and the entries
%% it could not use.
%%
%% **The second list is the point.** This was a comprehension with the two
%% filters as clauses, so an entry that failed either one simply did not appear
%% in the result and nothing recorded that it had been there. `f:process/2`
%% returning a short list was therefore indistinguishable from a bundle that
%% held a short list -- the exact shape of `#Q6NKB9P`, where a reseed of two
%% RouterInfos silently yielded one, the NetDb stayed a router short, and the
%% only log line anywhere said nothing. A filter this cheap does not need to be
%% silent to be cheap: a bundle is hundreds of entries and all of them match, so
%% the reporting path is empty on every real reseed.
take_entries(Entries) ->
    {Taken, Skipped} = lists:foldl(fun take_entry/2, {[], []}, Entries),
    %% **Entry order, not fold order.** Both accumulators are built by
    %% prepending, so the taken list comes out reversed; a caller reading the
    %% bundle in the order the mirror wrote it is not something to change
    %% quietly, and `i2p_reseed_tests:fetch_and_process/0` pins it.
    {lists:reverse(Taken), Skipped}.

take_entry({Name, Data}, {Ris, Skipped}) ->
    case ri_entry(Name) of
        true -> decode_entry(Name, Data, {Ris, Skipped});
        false -> {Ris, [{Name, not_a_router_info_entry} | Skipped]}
    end.

decode_entry(Name, Data, {Ris, Skipped}) ->
    case i2p_router_info:decode(Data) of
        {ok, RI} -> {[RI | Ris], Skipped};
        {error, Reason} -> {Ris, [{Name, Reason} | Skipped]}
    end.

report_skipped({Name, Reason}) ->
    i2p_log:emit(
        reseed_routerinfo_skipped,
        "reseed bundle entry ~0p skipped: ~0p",
        [Name, Reason]
    ).

%% ri_entry/1 — reseed zips carry routerInfo-<base64 hash>.dat files.
%%
%% Entry names arrive as strings or binaries depending on how they were written,
%% so normalise before matching.
%%
%% **The suffix is matched here, not with `filename:extension/1`.** That function
%% reads `/` as a directory separator, so a name whose hash ended in one put
%% `.dat` in what it considered the directory part and returned `<<>>` -- and
%% `f:take_entries/1` dropped the RouterInfo behind it. The hash bytes are not
%% this module's to constrain: a zip entry name is a name, and the bytes in it
%% are whatever the signed bundle put there. `#Q6NKB9P`.
ri_entry(Name0) ->
    is_router_info_name(iolist_to_binary(Name0)).

%% Clause pair rather than a `case`, so each answer is its own head. The two are
%% separate functions because a binary segment that is not last has to be followed
%% by a size, and the length of the hash between the prefix and the suffix is not
%% fixed -- it is whatever the signer wrote.
is_router_info_name(<<"routerInfo-", Rest/binary>>) ->
    is_dat_named(Rest);
is_router_info_name(_Name) ->
    false.

%% **A suffix, read off the end of the bytes.** See `f:ri_entry/1` for what this
%% replaced and why `filename:extension/1` cannot answer it.
is_dat_named(Rest) ->
    Size = byte_size(Rest),
    Size >= 4 andalso binary:part(Rest, Size - 4, 4) =:= <<".dat">>.

try_hosts([], _TrustStore, LastError) ->
    {error, LastError};
try_hosts([Host | Rest], TrustStore, _LastError) ->
    case try_host(Host, TrustStore) of
        {ok, _Ris} = Ok -> Ok;
        {error, Reason} -> try_hosts(Rest, TrustStore, Reason)
    end.

try_host(Host, TrustStore) ->
    case fetch(seeds_url(Host)) of
        {ok, Su3Bin} ->
            process(Su3Bin, TrustStore);
        {error, Reason} ->
            {error, Reason}
    end.
