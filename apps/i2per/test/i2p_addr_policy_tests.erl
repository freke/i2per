%% Unit tests for the shared address policy: the classification `m:i2per_sup`
%% gates a boot host on, and the relay punch gate `m:i2p_relay_coord` applies to
%% an endpoint a peer asserted.

-module(i2p_addr_policy_tests).

-moduledoc """
Tests for `m:i2p_addr_policy`.

Two callers depend on this module and neither is the other's, so the cases here
are grouped by the question each one is really asking. `m:i2per_sup` asks whether
**our own** configured host is publishable; `m:i2p_relay_coord` asks whether an
endpoint **a third party asserted** is one we will emit a datagram at. The
second is the security-relevant one, and it is deliberately the stricter
question: a private literal is a legitimate answer for a laptop and an
unacceptable one for a punch target.
""".

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% The families
%% --------------------------------------------------------------------------

%% One case per named family, on both encodings. RFC 1918 and `fc00::/7` are the
%% same concept and are tested as one, because a reader who had to know which
%% encoding was which would be reasoning about the encoding rather than the
%% answer.
family_classification_test() ->
    ?assertEqual(loopback, i2p_addr_policy:family({127, 0, 0, 1})),
    ?assertEqual(loopback, i2p_addr_policy:family({127, 255, 255, 254})),
    ?assertEqual(loopback, i2p_addr_policy:family({0, 0, 0, 0, 0, 0, 0, 1})),
    ?assertEqual(unspecified, i2p_addr_policy:family({0, 0, 0, 0})),
    ?assertEqual(unspecified, i2p_addr_policy:family({0, 0, 0, 0, 0, 0, 0, 0})),
    ?assertEqual(private, i2p_addr_policy:family({10, 1, 2, 3})),
    ?assertEqual(private, i2p_addr_policy:family({172, 16, 0, 1})),
    ?assertEqual(private, i2p_addr_policy:family({172, 31, 255, 255})),
    ?assertEqual(private, i2p_addr_policy:family({192, 168, 1, 1})),
    ?assertEqual(private, i2p_addr_policy:family({16#fc00, 0, 0, 0, 0, 0, 0, 1})),
    ?assertEqual(private, i2p_addr_policy:family({16#fdff, 0, 0, 0, 0, 0, 0, 1})),
    ?assertEqual(link_local, i2p_addr_policy:family({169, 254, 1, 1})),
    ?assertEqual(link_local, i2p_addr_policy:family({16#fe80, 0, 0, 0, 0, 0, 0, 1})),
    ?assertEqual(link_local, i2p_addr_policy:family({16#febf, 0, 0, 0, 0, 0, 0, 1})),
    ?assertEqual(multicast, i2p_addr_policy:family({224, 0, 0, 1})),
    ?assertEqual(multicast, i2p_addr_policy:family({16#ff02, 0, 0, 0, 0, 0, 0, 1})),
    ?assertEqual(public, i2p_addr_policy:family({8, 8, 8, 8})),
    ?assertEqual(public, i2p_addr_policy:family({172, 15, 0, 1})),
    ?assertEqual(public, i2p_addr_policy:family({172, 32, 0, 1})),
    ?assertEqual(public, i2p_addr_policy:family({16#2606, 16#4700, 0, 0, 0, 0, 0, 16#1111})).

%% `f:public/1` is the one that is not `public`, so it is worth pinning against
%% the whole family list rather than only the cases that matter.
public_is_the_complement_of_the_other_families_test() ->
    Addrs = [
        {127, 0, 0, 1},
        {0, 0, 0, 0},
        {10, 0, 0, 1},
        {172, 16, 0, 1},
        {192, 168, 0, 1},
        {169, 254, 0, 1},
        {224, 0, 0, 1},
        {16#fe80, 0, 0, 0, 0, 0, 0, 1},
        {16#fc00, 0, 0, 0, 0, 0, 0, 1},
        {16#ff02, 0, 0, 0, 0, 0, 0, 1},
        {0, 0, 0, 0, 0, 0, 0, 1},
        {8, 8, 8, 8}
    ],
    lists:foreach(
        fun(Addr) ->
            ?assertEqual(i2p_addr_policy:family(Addr) == public, i2p_addr_policy:public(Addr))
        end,
        Addrs
    ).

%% --------------------------------------------------------------------------
%% Ports
%% --------------------------------------------------------------------------

privileged_port_test() ->
    ?assert(i2p_addr_policy:privileged_port(0)),
    ?assert(i2p_addr_policy:privileged_port(1)),
    ?assert(i2p_addr_policy:privileged_port(1023)),
    ?assertNot(i2p_addr_policy:privileged_port(1024)),
    ?assertNot(i2p_addr_policy:privileged_port(49657)),
    ?assertNot(i2p_addr_policy:privileged_port(65535)).

%% --------------------------------------------------------------------------
%% The punch gate
%% --------------------------------------------------------------------------

%% An endpoint this router will send an unsolicited datagram at. The point of
%% the case is the *refusals*: this is the predicate standing between a public
%% i2per and somebody's internal network.
punchable_refuses_non_public_endpoints_test() ->
    lists:foreach(
        fun({Port, Ip}) ->
            ?assertNot(i2p_addr_policy:punchable(Port, Ip))
        end,
        [
            {49657, <<127, 0, 0, 1>>},
            {49657, <<10, 0, 0, 7>>},
            {49657, <<172, 20, 1, 1>>},
            {49657, <<192, 168, 1, 1>>},
            {49657, <<169, 254, 1, 1>>},
            {49657, <<0, 0, 0, 0>>},
            {49657, <<224, 0, 0, 1>>},
            {49657, <<16#fe80:16, 0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 16#0001:16>>},
            {49657, <<16#fc00:16, 0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 16#0001:16>>},
            %% A public address on a privileged port is still refused: the
            %% network reserves no low range, so no router publishes one.
            {1023, <<8, 8, 8, 8>>},
            {80, <<8, 8, 8, 8>>}
        ]
    ).

punchable_accepts_public_endpoints_test() ->
    ?assert(i2p_addr_policy:punchable(49657, <<8, 8, 8, 8>>)),
    ?assert(i2p_addr_policy:punchable(1024, <<8, 8, 8, 8>>)),
    ?assert(i2p_addr_policy:punchable(65535, <<8, 8, 8, 8>>)),
    ?assert(
        i2p_addr_policy:punchable(
            49657,
            <<16#2606:16, 16#4700:16, 0:16, 0:16, 0:16, 0:16, 0:16, 16#1111:16>>
        )
    ).

%% A wrong byte length is the same answer as a private address: the punch would
%% have nowhere to go. The codec fixes an endpoint at 4 or 16 bytes, so anything
%% else is a shape the wire cannot produce — but the predicate is the last thing
%% between the bytes and a `gen_udp:send`, and this is what says it does not
%% raise.
punchable_refuses_a_wrong_length_address_test() ->
    ?assertNot(i2p_addr_policy:punchable(49657, <<>>)),
    ?assertNot(i2p_addr_policy:punchable(49657, <<8, 8, 8>>)),
    ?assertNot(i2p_addr_policy:punchable(49657, <<8, 8, 8, 8, 8>>)),
    ?assertNot(i2p_addr_policy:punchable(49657, binary:copy(<<8>>, 15))),
    ?assertNot(i2p_addr_policy:punchable(49657, binary:copy(<<8>>, 17))).

%% --------------------------------------------------------------------------
%% The two omissions, pinned so they stay omissions
%% --------------------------------------------------------------------------

%% Documentation prefixes and carrier-grade NAT are deliberately public here.
%% Neither sits behind the stateful firewall whose established-session exception
%% is the entire reason a hole punch exists, and the documentation range is what
%% makes the punch path exercisable from a loopback test bed at all — a policy
%% that refused it would put the accept path out of reach of CI. If this case
%% ever fails, the decision changed and the module doc has to change with it.
documentation_and_cgnat_ranges_are_public_test() ->
    ?assert(i2p_addr_policy:public({192, 0, 2, 1})),
    ?assert(i2p_addr_policy:public({198, 51, 100, 1})),
    ?assert(i2p_addr_policy:public({203, 0, 113, 1})),
    ?assert(i2p_addr_policy:public({100, 64, 0, 1})),
    ?assert(i2p_addr_policy:family({16#2001, 16#0db8, 0, 0, 0, 0, 0, 1}) == public).
