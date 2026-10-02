-module(i2p_tcp_acceptor).

-moduledoc """
The only process that accepts a TCP connection, one per listening socket.

`m:i2p_ntcp2_listener` and `m:i2p_sam_listener` each own a listening socket and
answer for it; everything below the `accept` is this process's whole job. It
blocks in `f:gen_tcp:accept/1` and loops, so a connection is taken as soon as
the kernel has completed it.

## Why accepting needs a process of its own

A listening socket does not notify. `{active, true}` on it delivers nothing: no
`{tcp, ListenSock, Sock}`, and no message of any kind when a connection arrives.
That is not an option this module failed to set, it is how the driver works —
the inet driver only arms `FD_ACCEPT` on a listening socket while a
`gen_tcp:accept` call is outstanding (`inet_drv.c`, `INET_REQ_ACCEPT`, which is
the sole place `sock_select(..., FD_ACCEPT, 1)` appears). Verified on this tree
at OTP 28 with `{active, true}`, `{active, once}` and `{active, false}`: all
three accept identically, and none of them produces a message.

So a process that accepts must either block in `gen_tcp:accept` and answer
nothing while it does, or come back out of it on a timer to look at its mailbox.
Both `m:i2p_ntcp2_listener` and `m:i2p_sam_listener` used to do the second, with
a one-second timeout, and so each accepted exactly one inbound connection per
second no matter how many were waiting: a peer-set rebuild after a restart
converged one peer per second, and a SAM client that opened a second session
waited a second for it. The rate was exactly the timeout, not a load effect.

Which means the three control messages a listener is asked (`port`, `address`,
`stop`) are now answered by a process that is not blocked. The loops in those
modules have no timeout clause at all: there is nothing left to poll for, so a
message is answered when it is read.

## What the listener supplies, and what this owns

The split is: **this module owns the accept and the socket; the listener owns
what an accepted socket becomes.** The listener passes a `f:handler/1` — the
thing to do with a freshly accepted socket, which for both callers is a
`supervisor:start_child` followed by a `f:gen_tcp:controlling_process/2`
handover. That is the only per-resource knowledge here, and it stays in the
listener, next to the child spec it builds and the announcement the new owner
owes it.

The fun is built once, in the listener, and sent once in the start arguments.
It is called per connection, in this process, as a local fun — so the
abstraction costs a local call on the accept path and nothing else.

## The handover window, and why it is safe

Between the `accept` and the `controlling_process/2`, the accepted socket belongs
to *this* process, because the caller of `f:gen_tcp:accept/1` is who owns what it
returns. Nothing can be misrouted in between, and that rests on one option
rather than on the loop being quick.

An accepted socket **inherits its listen socket's active mode** — measured, not
assumed: the same accept over a `{active, true}` listener yields an accepted
socket that delivers `{tcp, Sock, Data}` to this process, and over a
`{active, false}` listener one that does not. So the listen socket is
`{active, false}` and the accepted socket is set `{active, false}` again here, at
the one place that owns it. Setting it again is deliberate even though it is
already the value: it makes the handover's safety a property of this module
rather than of an option a listener happens to pass, and it costs one field on a
socket that has no traffic on it yet.

A socket that cannot deliver cannot deliver to the wrong owner, whatever the
peer sends in that window.

## Lifetime

The listener owns the listening socket, so the listener's death is what stops
accepting: the socket closes, the blocked `f:gen_tcp:accept/1` answers
`{error, closed}`, and this process exits `normal`. The other direction is each
listener's to hold — it monitors this process and ends with it, so an acceptor
that crashed cannot leave behind a live listener pid that has quietly stopped
accepting, with every caller of its `port/1` still reporting a port nothing is
listening on.
""".

-export([start_link/2]).

-export([init/2]).

-doc """
What a listener wants done with an accepted socket.

The listener owns it end to end: start the child, hand the socket over, and tell
the new owner. Returns `ok` in every case, including a refusal — a child that
would not start has already had its socket closed by then — so the accept loop
has no policy of its own to get wrong.

**Ending in `ok` is part of the contract, and the loop asserts it.** It is a
contract a handler can get wrong *silently*, because the two natural mistakes
both compile and both return something:

- a handler whose last expression is a send returns **the message it sent**, not
  `ok` -- `Pid ! {socket_ready, Sock}` answers `{socket_ready, Sock}`;
- writing `ok = Pid ! {socket_ready, Sock}` does not fix it. `erlang:send/2`
  returns its first argument, so that match can never succeed, and the crash lands
  in the handler rather than in the loop that was supposed to be checking.

The answer is an explicit `ok` as the last expression. `m:i2p_sam_listener:handover/2`
is written that way, and the `ok =` in the loop below is what turns the other two
mistakes into a crash at the point where the contract is stated instead of a
handler quietly answering something nobody reads.
""".
-type handler() :: fun((gen_tcp:socket()) -> ok).

-doc false.
-spec start_link(gen_tcp:socket(), handler()) -> {ok, pid()} | {error, term()}.
start_link(ListenSock, Handler) ->
    proc_lib:start_link(?MODULE, init, [ListenSock, Handler]).

-doc false.
-dialyzer({no_underspecs, init/2}).
-spec init(gen_tcp:socket(), handler()) -> no_return().
init(ListenSock, Handler) ->
    %% Acknowledged before the first `accept`, so the caller's `listen/N` does not
    %% return until the door is armed. A connection that lands in between the
    %% socket being bound and the acceptor being armed would sit in the kernel's
    %% backlog and be taken microseconds later, so this is not a correctness
    %% requirement — it is the difference between "the listener is up" meaning the
    %% accept path is running and meaning only that a socket exists.
    proc_lib:init_ack({ok, self()}),
    accept_loop(ListenSock, Handler).

accept_loop(ListenSock, Handler) ->
    case gen_tcp:accept(ListenSock) of
        {ok, Sock} ->
            ok = inet:setopts(Sock, [{nodelay, true}, {keepalive, true}, {active, false}]),
            ok = Handler(Sock),
            accept_loop(ListenSock, Handler);
        {error, closed} ->
            %% The listener closed the socket on its way out. This is the ordinary
            %% end of this loop and the reason a listener's `stop/1` can answer
            %% before this process has finished exiting.
            exit(normal);
        {error, Reason} ->
            %% A resource limit or an error this loop has no way to work around
            %% (`emfile` on a busy node is the one worth naming). It stops
            %% accepting, and the listener ends with it, so the supervisor sees a
            %% listener that is not accepting rather than a router that looks
            %% healthy and refuses connections. The reason is in the exit because
            %% the shape this replaced — a `case_clause` on the same value — said
            %% nothing about which value it was.
            exit({accept_failed, Reason})
    end.
