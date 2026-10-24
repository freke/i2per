-module(i2per_proxy_relay).

-moduledoc """
Bidirectional byte relay between two TCP sockets.

Runs in the caller's process and blocks until either side closes or the
timeout elapses. Used by both the HTTP and the SOCKS proxy handlers.
""".

-export([relay/2, relay/3]).

-spec relay(gen_tcp:socket(), gen_tcp:socket()) -> ok.
relay(A, B) ->
    relay(A, B, 300000).

-spec relay(gen_tcp:socket(), gen_tcp:socket(), timeout()) -> ok.
relay(A, B, Timeout) ->
    Parent = self(),
    P1 = spawn_link(fun() -> forward(A, B, Parent) end),
    P2 = spawn_link(fun() -> forward(B, A, Parent) end),
    receive
        {done, P1} ->
            receive
                {done, P2} -> ok
            after 5000 -> ok
            end;
        {done, P2} ->
            receive
                {done, P1} -> ok
            after 5000 -> ok
            end
    after Timeout ->
        exit(P1, kill),
        exit(P2, kill),
        ok
    end.

forward(Src, Dst, Parent) ->
    case gen_tcp:recv(Src, 0, 30000) of
        {ok, Data} ->
            case gen_tcp:send(Dst, Data) of
                ok -> forward(Src, Dst, Parent);
                {error, _} -> Parent ! {done, self()}
            end;
        {error, _} ->
            Parent ! {done, self()}
    end.
