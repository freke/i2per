-module(i2per_tun_tun).

-moduledoc """
Facade over the `i2per_tun_nif` Rust NIF (epiq `D3750BZ` fd spike).

One resource per call to `f:open/1`: the NIF opens `/dev/net/tun`, claims the
named interface with `TUNSETIFF` (`IFF_TUN | IFF_NO_PI`), and leaves it
non-blocking. `f:read/1` and `f:write/2` move single IP packets without ever
blocking a scheduler, and `f:arm/2` asks the runtime to send
`{i2per_tun_ready, Dev}` to a process when the device has a packet to read.
Readiness is one-shot: drain, then arm again.

Errors are posix atoms (`eacces`, `eagain`, `enodev`, ...), `{errno, N}` for
an errno without a stable name, or `nif_panic` when a panic in the Rust crate
was caught at the NIF boundary — the crash-containment story this spike
exists to demonstrate.
""".

-on_load(init/0).

-export([version/0, open/1, read/1, write/2, arm/2, stop/1]).

-opaque dev() :: term().

-export_type([dev/0]).

%% The `.so` is built by scripts/build-i2per-tun-nif.sh into the app's priv/.
%% The source-tree fallback covers runs where the app is on the path but not
%% installed as a release app.
init() ->
    Path =
        case code:priv_dir(i2per_tun) of
            {error, _} ->
                Dir = filename:dirname(code:which(?MODULE)),
                filename:join([Dir, "..", "priv", "i2per_tun_nif"]);
            Dir ->
                filename:join(Dir, "i2per_tun_nif")
        end,
    ok = erlang:load_nif(Path, 0),
    ok.

-doc "NIF sanity probe; also the test seam for \"is the .so built and loaded\".".
-spec version() -> binary().
version() ->
    erlang:nif_error(not_loaded).

-doc """
Claim the TUN interface named `Name` (1..15 bytes, IFNAMSIZ). Needs
CAP_NET_ADMIN; without it the error is `eacces` or `eperm`, which is the
expected shape on an unprivileged host rather than a defect.
""".
-spec open(binary()) -> {ok, dev()} | {error, term()}.
open(_Name) ->
    erlang:nif_error(not_loaded).

-doc """
One non-blocking read: `{ok, Packet}` (one IP packet), `{error, eagain}` when
the queue has drained (re-arm), or another posix error.
""".
-spec read(dev()) -> {ok, binary()} | {error, term()}.
read(_Dev) ->
    erlang:nif_error(not_loaded).

-doc """
One packet-atomic write. TUN cannot deliver half a packet, so a short write is
reported as an error rather than retried here.
""".
-spec write(dev(), binary()) -> ok | {error, term()}.
write(_Dev, _Packet) ->
    erlang:nif_error(not_loaded).

-doc """
Arm one read-readiness notification for `Pid`: when the device has a packet,
the runtime sends `{i2per_tun_ready, Dev}`. One shot per call.
""".
-spec arm(dev(), pid()) -> ok | {error, term()}.
arm(_Dev, _Pid) ->
    erlang:nif_error(not_loaded).

-doc """
Stop selecting the device. The fd is closed by the NIF's stop callback, which
may run after this call returns.
""".
-spec stop(dev()) -> ok | {error, term()}.
stop(_Dev) ->
    erlang:nif_error(not_loaded).
