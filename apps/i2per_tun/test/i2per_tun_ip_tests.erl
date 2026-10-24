-module(i2per_tun_ip_tests).

-include_lib("eunit/include/eunit.hrl").

parse_ipv4_test() ->
    Pkt =
        <<4:4, 5:4, 0:8, 40:16, 0:16, 0:16, 64:8, 6:8, 0:16, 10, 0, 0, 1, 10, 0, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
    ?assertMatch(
        {ok, #{version := 4, protocol := 6, src := {10, 0, 0, 1}, dst := {10, 0, 0, 2}}},
        i2per_tun_ip:parse(Pkt)
    ).

parse_bad_test() ->
    ?assertMatch({error, _}, i2per_tun_ip:parse(<<1, 2, 3>>)).

tcp_parse_test() ->
    Seg = <<80:16, 443:16, 0:32, 0:32, 5:4, 0:4, 2:8, 1000:16, 0:16, 0:16, "hello">>,
    ?assertMatch({ok, #{src_port := 80, dst_port := 443}}, i2per_tun_ip:tcp_parse(Seg)).

udp_parse_test() ->
    Seg = <<53:16, 5353:16, 10:16, 0:16, "hi">>,
    ?assertMatch({ok, #{src_port := 53, dst_port := 5353}}, i2per_tun_ip:udp_parse(Seg)).

flow_key_tcp_test() ->
    {ok, Pkt} = i2per_tun_ip:parse(
        <<4:4, 5:4, 0:8, 40:16, 0:16, 0:16, 64:8, 6:8, 0:16, 10, 0, 0, 1, 10, 0, 0, 2, 80:16,
            443:16, 0:32, 0:32, 5:4, 0:4, 0:8, 0:16, 0:16, 0:16, "x">>
    ),
    ?assertEqual({tcp, {10, 0, 0, 1}, {10, 0, 0, 2}, 80, 443}, i2per_tun_ip:flow_key(Pkt)).
