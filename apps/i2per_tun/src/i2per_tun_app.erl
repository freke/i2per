-module(i2per_tun_app).

-moduledoc """
The `i2per_tun` OTP application callback — the 0.8.0 fd spike (epiq
`D3750BZ`).

Deliberately **not** started together with the router, like `i2per_status`:
it is a companion app (ADR 0001) and, being a spike, starting it cannot
succeed unprivileged — the TUN open needs CAP_NET_ADMIN. This spike's driver
starts it explicitly with
`application:ensure_all_started(i2per_tun)` on a privileged host.
""".

-behaviour(application).

-export([start/2, stop/1]).

-spec start(application:start_type(), term()) -> {ok, pid()}.
start(_Type, _Args) ->
    i2per_tun_sup:start_link().

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
