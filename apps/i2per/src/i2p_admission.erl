-module(i2p_admission).

-moduledoc """
Admits a supervised child under a limit, and owns the check that makes the limit
hold.

One instance per bounded resource — NTCP2 connections, SSU2 sessions, SAM
sessions — and each is a child of the very supervisor whose children it admits.
`f:admit/2` is the whole API: hand it a child spec and it answers with what
`m:supervisor:start_child/2` would have answered, or `{error, Refused}`.

## The cap is a count-then-start, and that is the only reason this exists

A limit is a limit only if the count and the start are atomic together. Read the
count, see there is room, start the child: three steps, and three steps is a
race. The moments that matter are exactly the moments the cap exists for — a
router coming up after a restart, a peer set being rebuilt, a floodfill
replication burst bringing in a wave of new peers — and those are when many
handshakes complete in the same instant, so the count is most likely to be read
twice before either start lands.

So the two have to be serialised, and this process is what serialises them. The
count and the `m:supervisor:start_child/2` that follows it happen in one
reduction of one process, so no second admission can read a count this one has
already acted on.

**Nothing is cached here, and that is what makes it hold.** The count is read
from the supervisor, which is the only thing that knows which children are
alive; this process is the only thing that can add one. There is no second copy
to fall out of step with the first. A restarted admission process is a *free*
restart: no state to rebuild, no total to reconcile, and no window in which the
cap is being enforced against a number nobody has checked.

## Why not `global:trans/2`, which is what this replaced

**It is not a mutex, and the tree was using it as one.** That is the whole reason
it is gone, and it is worth reading before anything else here.

`m:global:set_lock/3` says so itself:

> The global name server keeps track of all processes sharing the same lock, that
> is, if two processes set the same lock, both processes must delete the lock.

A lock id is `{ResourceId, LockRequesterId}`, and the name server matches on the
**pair**: `can_set_lock/1` answers "already held" for a matching pair regardless
of which process holds it, and `handle_set_lock/3` then *adds* the new process to
the holder list and answers `true`. So `global:trans/2` from N processes using one
id is a **cooperative, shared, re-entrant** lock, and all N of them run `Fun()`.
That is a useful thing for a lock to be. It is not what a count-then-start needs.

It only *looks* exclusive when the critical section is short. `set_lock/4` waits by
retrying through `random_sleep/1`, so a process that loses the first attempt comes
back later — and if the holder is still inside by then, the retry is granted as
well. Measured on this tree, OTP 28, twelve processes on one id:

| body of `Fun()` | most processes inside at once |
|---|---|
| returns immediately | 1 |
| sleeps 2 ms | 12 |
| sleeps 20 ms | 12 |

The section here is a supervision-tree walk and a process start, so it is
milliseconds rather than microseconds. **Measured against the code as it stood,
with a cap of 4 and 24 dials released together: 8, 10 and 24 admitted for NTCP2,
SSU2 and SAM on successive runs.** The cap was advisory — on exactly the paths, a
post-restart peer-set rebuild or a floodfill replication burst, where many
handshakes complete at once.

## The other two reasons, which are real but smaller

**The lock is cluster-wide and the number is not.** `global:trans/2` is
`trans(Id, Fun, [node() | nodes()], infinity)` — OTP 28, `m:global` — so it reaches
every connected node, while the cap it was guarding counts this node's children.
This project supports a second node: `i2per_status` is a separate application, it
may run on its own node, and it reaches the router over Erlang distribution. Even
had the lock excluded, a second node would have serialised this router's connection
admissions against its own for a limit neither can see past.

**Even as a cooperative lock it is somebody else's process, and it retries at
random.** `set_lock/3` is a `gen_server:multi_call/4` to `global_name_server`, which
holds every distributed lock in the VM — on a node whose shipped configuration has
no peers for it to be talking to — and `set_lock/4` backs off through
`random_sleep/1`, doubling to eight seconds. Admission latency under the burst the
cap exists for would be random rather than bounded, which is a property an operator
watching a peer set fail to rebuild cannot reason about.

Neither of those needed fixing on its own. What needed fixing was that the cap did
not hold, and the reason is the section above this one.

## One instance per resource, and why not one for all of them

The three caps bound three different things — handshake state, handshake state,
and client sockets — behind three separate configuration keys, so they were
never one number. What *was* shared was the wait. Under a single admission
process, a floodfill burst bringing in a wave of new peers queues ahead of an
operator's SAM session, which is the one connection an operator is waiting on by
hand.

Separate instances have separate mailboxes, so the three never wait on each
other. A peer dial that loses a race to the cap now loses it against other peer
dials, and a SAM session is admitted at its own rate.

## Usage

```erlang
{ok, Session} = i2p_admission:admit(i2p_sam_admission, i2p_sam_sup:session_child(Args)),
%% ... and once `max_sam_sessions` of them are live:
{error, session_limit} = i2p_admission:admit(i2p_sam_admission, i2p_sam_sup:session_child(Args)).
```
""".

-behaviour(gen_server).

-export([child_spec/1, start_link/1, admit/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-export_type([config/0]).

-doc """
One admission process's configuration.

`name` is what the process registers as, and what `f:admit/2` takes.
`supervisor` is the supervisor whose children are started and counted. `count`
and `limit` are read on every admission, not once at start, so a limit an
operator changes takes effect on the next connection rather than the next boot.
`refused` is the atom a refusal is reported as — each resource has its own, and
callers match on it. `refused_counter` is the `m:i2p_stats` counter a refusal is
charged to.
""".
-type config() :: #{
    name := atom(),
    supervisor := atom(),
    count := fun(() -> non_neg_integer()),
    limit := fun(() -> non_neg_integer()),
    refused := atom(),
    refused_counter := atom()
}.

-doc """
A `permanent` child spec for one admission process.

`permanent`, and the reason is that this process *is* the cap. A cap that has
quietly gone missing is worse than a router that declines to start, so a crash
here is the supervisor's to notice rather than something the resource carries on
without. And because nothing is held, a restart costs nothing and has nothing to
rebuild — see the module doc.
""".
-spec child_spec(config()) -> supervisor:child_spec().
child_spec(Config) ->
    #{
        id => admission,
        start => {?MODULE, start_link, [Config]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [?MODULE]
    }.

-doc """
Admit and start one child under this resource's limit.

Input: the registered name of an admission process, and a
`supervisor:child_spec()`. Output: the `m:supervisor:start_child/2` result, or
`{error, Refused}` when the limit is already reached.

**Bounded by infinity, and that is inherited rather than chosen.**
`m:supervisor:start_child/2` blocks for as long as it takes and defaults to the
same, so a finite timeout here would invent a failure the path did not have: an
admission that gave up would take down whichever connection process was
admitting, where before it waited. What this removes is the wait behind *other
admissions*, not the wait for this one's child.
""".
-spec admit(atom(), supervisor:child_spec()) -> {ok, pid()} | {ok, pid(), term()} | {error, term()}.
admit(Name, ChildSpec) ->
    gen_server:call(Name, {admit, ChildSpec}, infinity).

-doc false.
-spec start_link(config()) -> {ok, pid()} | {error, term()}.
start_link(Config) ->
    gen_server:start_link({local, maps:get(name, Config)}, ?MODULE, Config, []).

%%% %%%%% %%% gen_server %%%%% %%%

%% The configuration, unchanged. There is no count here to bring up to date and
%% nothing to tear down, which is the whole reason a crash here is survivable.
init(Config) ->
    {ok, Config}.

%% No catch-all clause on purpose. The only request this process answers is an
%% admission, and one that is not is a caller's bug — which should end the
%% caller, not be absorbed here and answered with a shape nobody handles.
handle_call({admit, ChildSpec}, _From, Config) ->
    {reply, start_or_refuse(ChildSpec, Config), Config}.

handle_cast(_Msg, Config) ->
    {noreply, Config}.

handle_info(_Info, Config) ->
    {noreply, Config}.

terminate(_Reason, _Config) ->
    ok.

code_change(_OldVsn, Config, _Extra) ->
    {ok, Config}.

%%% %%%%% %%% Internal %%%%% %%%

%% The whole mechanism, and it is four lines because the two hard parts are
%% structural rather than written here: the count and the start cannot be
%% interleaved with another admission's, because this reduction has no `receive`
%% in it; and the count cannot go stale between the two, because the only thing
%% that can change it is the call on the next line.
start_or_refuse(ChildSpec, Config) ->
    #{supervisor := Sup, count := Count, limit := Limit} = Config,
    case Count() >= Limit() of
        true -> refuse(Config);
        false -> supervisor:start_child(Sup, ChildSpec)
    end.

%% Charged here rather than by each caller, so "how often is a cap being hit" has
%% one answer per resource instead of three call sites to remember. A counter
%% and not an event: at the cap this fires on every inbound accept and on every
%% reconnect attempt, so it is a rate an operator watches rather than an incident
%% worth one bus message each.
refuse(Config) ->
    #{refused := Refused, refused_counter := Counter} = Config,
    ok = i2p_stats:add(Counter, 1),
    {error, Refused}.
