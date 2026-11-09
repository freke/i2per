-module(i2per_proxy_relay).

-moduledoc """
Bidirectional byte relay between two TCP sockets.

Runs in the caller's process and blocks until either side closes or the idle
timeout elapses. The timeout is an *idle* timeout: any byte in either direction
restarts it, so a connection is closed only when both directions have been
quiet for the whole interval. `relay/2` reads it from
`m:i2per_proxy_config:relay_idle_timeout/0` (disabled by default, matching
i2pd); `relay/3` takes it explicitly. Used by both the HTTP and the SOCKS proxy
handlers.
""".

-export([relay/2, relay/3]).

-spec relay(gen_tcp:socket(), gen_tcp:socket()) -> ok.
relay(A, B) ->
    relay(A, B, i2per_proxy_config:relay_idle_timeout()).

-spec relay(gen_tcp:socket(), gen_tcp:socket(), timeout()) -> ok.
relay(A, B, Timeout) ->
    keepalive(A),
    keepalive(B),
    Parent = self(),
    P1 = spawn_link(fun() -> forward(A, B, Parent) end),
    P2 = spawn_link(fun() -> forward(B, A, Parent) end),
    wait(P1, P2, Timeout).

%% Without an application-level idle timeout, the OS keepalive is what notices
%% a peer that vanished without closing its socket. Best-effort: a socket that
%% refuses the option (for instance one owned by another process) still relays.
keepalive(Sock) ->
    _ = inet:setopts(Sock, [{keepalive, true}]),
    ok.

wait(P1, P2, Timeout) ->
    receive
        {done, P1} ->
            await(P2, 5000);
        {done, P2} ->
            await(P1, 5000);
        {activity, _} ->
            wait(P1, P2, Timeout)
    after Timeout ->
        exit(P1, kill),
        exit(P2, kill),
        ok
    end.

%% One direction has closed. Give the other a moment to flush what is already
%% in flight, then return so the caller closes both sockets.
await(P, Timeout) ->
    receive
        {done, P} -> ok
    after Timeout -> ok
    end.

forward(Src, Dst, Parent) ->
    case gen_tcp:recv(Src, 0, 30000) of
        {ok, Data} ->
            case gen_tcp:send(Dst, Data) of
                ok ->
                    Parent ! {activity, self()},
                    forward(Src, Dst, Parent);
                {error, _} ->
                    Parent ! {done, self()}
            end;
        {error, timeout} ->
            %% An idle direction is normal: keep the relay alive and let the
            %% shared idle timer in wait/3, not this per-read timeout, bound it.
            forward(Src, Dst, Parent);
        {error, _} ->
            Parent ! {done, self()}
    end.
