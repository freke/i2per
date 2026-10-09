%%%-------------------------------------------------------------------
%%% @author i2per
%%% @doc One predicate for "is this address on the public internet".
%%%
%%% Two callers need it and neither is the other's caller. `m:i2per_sup` asks it
%%% of the address the operator configured, so the router never publishes a
%%% RouterInfo it cannot be dialed on. `m:i2p_relay_coord` asks it of the
%%% endpoint a *peer asserted* in a RelayIntro, so a public i2per cannot be used
%%% to send a datagram at somebody's internal network.
%%%
%%% They were two copies of the same case expression, and a security predicate
%%% with a second copy is a predicate that will be widened in one of them.
%%% @end
%%%-------------------------------------------------------------------
-module(i2p_addr_policy).

-moduledoc """
One answer to "is this IP literal on the public internet".

## Two callers, one predicate

`m:i2per_sup` asks it of **our own** configured host: a loopback or private
RouterInfo is undialable, so publishing one would put a router on the live
network nobody can reach. `m:i2p_relay_coord` asks it of **Alice's asserted
endpoint**, which is a value a third party chose and signed: punching at it is
this router emitting an unsolicited datagram at an address of somebody else's
choosing, and without the check a public i2per would be usable to probe an
internal network on a stranger's behalf.

The second question is why this is a module rather than a guard inside one of
the callers. It is the second time this project has needed the answer, and the
two needs fail together — a predicate that was right for the boot host and too
weak for a peer's assertion is how a firewall check quietly becomes a no-op.

## What counts as public

`t:family/0` names the six classes, and `f:public/1` is the one that is not
`public`. IPv4 uses the classic reserved list: `127/8` loopback, zero-host,
RFC 1918, `169.254/16` link-local, and `224/4` onward. IPv6 is the UCA split:
`::1`, `::`, `fe80::/10`, `fc00::/7`, `ff00::/8`.

**Two exclusions are deliberate, because they are the two a reader will look
for.** Documentation prefixes (`192.0.2.0/24`, `2001:db8::/32`) and carrier-grade
NAT (`100.64.0.0/10`) are *public* here. Neither is a NAT-traversal hazard —
neither sits behind a stateful firewall whose established-session exception is
the entire reason a hole punch exists. And the documentation range is what lets
the punch path be exercised from a loopback test bed at all: a policy that
refused it would make the accept path unreachable in CI, which is a worse trade
than naming the range in a comment.
""".

-export([family/1, public/1, privileged_port/1, punchable/2]).

-doc "The address classes this module distinguishes, for IPv4 and IPv6 alike.".
-export_type([family/0]).
-type family() :: loopback | unspecified | private | link_local | multicast | public.

%% %%%%% %%% Public API %%%%% %%%

-doc """
Classify an IP literal.

Input: an `inet:ip_address()` — an IPv4 or IPv6 tuple. Output: the `t:family/0`
it belongs to.

A shape that is neither family is classified `public` rather than raising. The
callers are a boot validation that has already parsed the literal and a relay
endpoint whose length the codec has already fixed at 4 or 16 bytes, so neither
can produce anything else; a predicate that raised on a shape its callers cannot
build is a predicate that needs a `catch` at both of them.

Note that RFC 1918 and `fc00::/7` are one class here, named `private`. They are
the same concept in two encodings, and a reader who had to know which is which
would be reasoning about the encoding rather than the answer.
""".
-spec family(inet:ip_address()) -> family().
family(Addr) when is_tuple(Addr), tuple_size(Addr) == 4 -> family4(Addr);
family({0, 0, 0, 0, 0, 0, 0, 1}) -> loopback;
family({0, 0, 0, 0, 0, 0, 0, 0}) -> unspecified;
family({Hi, _, _, _, _, _, _, _}) when Hi band 16#FFC0 =:= 16#FE80 -> link_local;
family({Hi, _, _, _, _, _, _, _}) when Hi band 16#FE00 =:= 16#FC00 -> private;
family({Hi, _, _, _, _, _, _, _}) when Hi band 16#FF00 =:= 16#FF00 -> multicast;
family(_) -> public.

family4({127, _, _, _}) -> loopback;
family4({0, _, _, _}) -> unspecified;
family4({10, _, _, _}) -> private;
family4({172, B, _, _}) when B >= 16, B =< 31 -> private;
family4({192, 168, _, _}) -> private;
family4({169, 254, _, _}) -> link_local;
family4({A, _, _, _}) when A >= 224 -> multicast;
family4(_) -> public.

-doc """
`true` when the address is on the public internet — `false` for every
`t:family/0` except `public`.

Input: an `inet:ip_address()`. Output: a boolean.
""".
-spec public(inet:ip_address()) -> boolean().
public(Addr) ->
    family(Addr) == public.

-doc """
`true` when `Port` is a privileged port, i.e. below 1024.

A peer asserting one is wrong or probing, and in neither case is it a router's
SSU2 endpoint: the network reserves no low range, and every listener a router
publishes sits above 1023.

Input: a port number. Output: a boolean.
""".
-spec privileged_port(0..65535) -> boolean().
privileged_port(Port) when Port < 1024 -> true;
privileged_port(_Port) -> false.

-doc """
Whether an asserted relay endpoint is one this router will punch at.

The relay endpoint hardening as one predicate: the asserted bytes must be an IP
literal the codec produced (4 or 16 — IPv4 then IPv6) and the address it names
must be public, and the port must not be privileged.

Input: the asserted `Port`; the asserted `Ip` bytes exactly as they arrived on
the wire — 4 or 16 of them. Output: `true` when the endpoint is punchable.

The bytes become a tuple here because `f:public/1` reads an
`inet:ip_address()`, and an IPv6 literal is sixteen bytes against `family/1`'s
eight sixteen-bit groups. Eight groups, then the rest discarded: the families are
named on the first group alone, so the other seven carry no information. The
arity is the whole care in this function — `f:family/1` dispatches on
`tuple_size == 4`, so an IPv6 literal folded into four groups is classified as
IPv4 and `2606::` comes back `multicast`.

A wrong byte length is `false`, which is the same answer as a private address
for the same reason: the punch would have nowhere to go, and one predicate
answering one question is worth more than the caller distinguishing two ways of
failing.
""".
-spec punchable(0..65535, binary()) -> boolean().
punchable(Port, Ip) when is_binary(Ip), byte_size(Ip) == 4 ->
    punchable_endpoint(Port, list_to_tuple(binary_to_list(Ip)));
punchable(Port, Ip) when is_binary(Ip), byte_size(Ip) == 16 ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16, _/binary>> = Ip,
    punchable_endpoint(Port, {A, B, C, D, E, F, G, H});
punchable(_Port, _Ip) ->
    false.

%% %%%%% %%% Internal %%%%% %%%

-spec punchable_endpoint(0..65535, inet:ip_address()) -> boolean().
punchable_endpoint(Port, Addr) ->
    %
    public(Addr) andalso not privileged_port(Port).
