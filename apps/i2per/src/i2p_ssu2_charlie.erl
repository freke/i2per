-module(i2p_ssu2_charlie).

-moduledoc """
The out-of-session Charlie peer-test responder.

A router that answers peer tests as Charlie gets an Alice message 6 addressed
straight to its introduction key, with no session in front of it. That is why the
responder is not a session process: there is no session to attach it to, which is
precisely why `m:i2p_ssu2_listener` used to answer inline.

Inline was the wrong home for two measured reasons. Answering one probe is
**6.7 µs** — an AEAD decrypt, a block rebuild and an AEAD encrypt — against
**0.73 µs** to route a datagram, so the socket owner spent nine times the effort
on the job that only sometimes applies as on the job that always does. And the
socket owner is the only process that can send, so its time is also every other
session's send latency. The work belongs off it.

So it is here: a cast in, a cast out. The listener classifies, and if the datagram
is an out-of-session probe it casts `f:answer/4` and returns to the socket
immediately. This process decodes, answers, and casts the reply to `f:reply/2`
for the listener to put on the wire.

The eight passes per probe are four to decode it (three to open the long header,
one AEAD decrypt) and four to build the reply (one AEAD encrypt, three to seal
the header), which is why the role is worth 6.80 µs to keep off a process whose
whole job for every other datagram is 0.76.

## Why one process per listener, not one per probe

There is no connection to hang a process off. A probe is a single datagram with a
single reply, so a per-probe process would be spawned and destroyed per datagram —
and under the flood that motivates the move, spawning is the expensive part. One
responder per listener is enough: the work is microseconds, the queue is bounded by
the rate probes arrive, and a peer that floods still cannot make the socket owner
do more than one cast per datagram.

A cast, not a call, and that is the property that matters: a slow responder
lengthens the responder's queue and nothing else. The listener never waits on it,
so a responder that is busy, or dead, or wedged cannot delay datagram
classification. `m:i2p_ssu2_sup` restarts it, and the listener monitors it, so the
role recovers on its own.

## Crash containment

This process exists partly because the work is unauthenticated. Anyone who knows
the introduction key — published in our own SSU2 RouterAddress — can make this
run. It was reachable that way from inside the listener, where a crash cost every
SSU2 session its send path, and #YNBT5ZD is the bug that proved it. Here a crash
costs one responder.

## What it holds

Only the introduction key, which is public. It holds no peer state, so a hostile
probe has nothing to corrupt between calls: the reply is a function of the probe
alone.
""".

-behaviour(gen_server).

-export([
    start_link/1,
    answer/4,
    reply/2,
    stop/1,
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-doc """
What this process hands back to the listener: a ready-to-send datagram and the
endpoint it belongs to. It carries sealed bytes rather than the decoded probe,
because the listener's only remaining job is to put them on the socket.
""".
-export_type([reply/0]).
-opaque reply() :: {binary(), {inet:ip_address(), inet:port_number()}}.

%% ------------------------------------------------------------------
%% API

-doc """
Start the responder for one listener.

Input: the `IntroKey` this router publishes, under which probes arrive.
Output: `{ok, Pid}`.
""".
-spec start_link(i2p_crypto:key()) -> {ok, pid()} | {error, term()}.
start_link(IntroKey) ->
    gen_server:start_link(?MODULE, IntroKey, []).

-doc """
Answer an out-of-session Alice message 6.

Cast rather than call, deliberately — see the module doc. Nothing is returned and
nothing is waited for, which is what keeps this off the socket owner's critical
path.

Input: this responder; the listener to reply through; the probe datagram; its
source endpoint. Output: `ok`. The reply, if any, arrives at `f:reply/2` on the
listener.
""".
-spec answer(pid(), pid(), binary(), {inet:ip_address(), inet:port_number()}) -> ok.
answer(Responder, Listener, Datagram, Endpoint) ->
    gen_server:cast(Responder, {answer, Listener, Datagram, Endpoint}).

-doc """
Hand a finished reply to the listener for sending.

Input: the listener and a `t:reply/0`. Output: `ok`.
""".
-spec reply(pid(), reply()) -> ok.
reply(Listener, Reply) ->
    gen_server:cast(Listener, {charlie_reply, Reply}).

-doc "Stop the responder.".
-spec stop(pid()) -> ok.
stop(Responder) ->
    gen_server:stop(Responder).

%% ------------------------------------------------------------------
%% gen_server

init(IntroKey) when is_binary(IntroKey) ->
    {ok, IntroKey}.

handle_call(_Other, _From, State) ->
    {noreply, State}.

%% Only message 6 is answered. Message 5 is Charlie->Alice and message 7 is our own
%% reply echoing it back, so neither is a request; a probe carrying anything else
%% is not something we answer, and it is dropped without a block scan.
%%
%% The guard is not a validation layer, it is a cheap gate: an empty datagram cannot
%% be a probe, and refusing it here costs a comparison instead of a ChaCha20 pass
%% inside `f:decode_peertest/2`. Everything else is decided in `handle_answer/4`,
%% where a decode failure is an ordinary `error` answer rather than a crash.
handle_cast({answer, Listener, Datagram, Endpoint}, Key) when
    is_binary(Datagram), byte_size(Datagram) > 0
->
    {noreply, handle_answer(Listener, Datagram, Endpoint, Key)};
handle_cast({answer, _Listener, _Datagram, _Endpoint}, Key) ->
    {noreply, Key}.

handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%% ------------------------------------------------------------------
%% The role

%% Decode, rebuild, answer. Every failure is a drop rather than a raise. The input
%% is unauthenticated, and `f:i2p_ssu2:finish_symmetric/7` is reached with
%% whatever length the datagram happened to have; the library answers `error` on a
%% short one (#YNBT5ZD), so every branch here has to decide too.
handle_answer(Listener, Datagram, Endpoint, Key) ->
    case i2p_ssu2:decode_peertest(Key, Datagram) of
        {ok, #{blocks := Blocks}} -> handle_blocks(Listener, Endpoint, Key, Blocks);
        _NotAPeerTest -> ok
    end.

handle_blocks(Listener, Endpoint, Key, Blocks) ->
    case lists:keyfind(peertest, 1, Blocks) of
        {peertest, 6, _Code, _Flags, _Hash, _Ver, Nonce, Ts, Port, Ip, _Sig} ->
            reply(Listener, {reply_packet(Key, Nonce, Ts, Port, Ip), Endpoint}),
            ok;
        _Other ->
            ok
    end.

%% Message 7, echoing Alice's nonce, timestamp and asserted endpoint back with no
%% hash and no signature: both are optional out-of-session. The connection IDs are
%% the nonce pair, which is how Alice recognises the reply as coming from us.
reply_packet(Key, Nonce, Ts, Port, Ip) ->
    Reply = i2p_peertest:block(7, 0, 0, <<>>, 2, Nonce, Ts, Port, Ip, <<>>),
    {ok, Packet} =
        i2p_ssu2:encode_peertest(
            Key,
            0,
            i2p_peertest:dst_conn_id(Nonce),
            i2p_peertest:src_conn_id(Nonce),
            [Reply]
        ),
    Packet.
