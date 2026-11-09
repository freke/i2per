-module(i2per_proxy_relay_tests).

-include_lib("eunit/include/eunit.hrl").

relay_closes_cleanly_test() ->
    {RelayA, PeerA} = pair(),
    {RelayB, PeerB} = pair(),
    Self = self(),
    spawn(fun() ->
        Self ! {relayed, i2per_proxy_relay:relay(RelayA, RelayB, 2000)}
    end),
    gen_tcp:close(PeerA),
    gen_tcp:close(PeerB),
    receive
        {relayed, Result} -> ?assertEqual(ok, Result)
    after 10000 ->
        ?assert(false)
    end.

%% The timeout is an idle timeout, not a wall-clock limit: bytes in either
%% direction restart it. Six ticks 100 ms apart span 600 ms, longer than the
%% 200 ms timeout, so an absolute timer would cut the relay at 200 ms.
idle_timeout_is_reset_by_traffic_test_() ->
    {"a relay lives longer than its idle timeout while bytes keep flowing",
        {timeout, 30, fun idle_timeout_is_reset_by_traffic/0}}.

idle_timeout_is_reset_by_traffic() ->
    {RelayA, PeerA} = pair(),
    {RelayB, PeerB} = pair(),
    Relay = spawn(fun() -> i2per_proxy_relay:relay(RelayA, RelayB, 200) end),
    try
        lists:foreach(
            fun(N) ->
                timer:sleep(100),
                ok = gen_tcp:send(PeerA, <<N:8>>),
                {ok, <<N:8>>} = gen_tcp:recv(PeerB, 1, 2000)
            end,
            lists:seq(1, 6)
        ),
        ?assert(is_process_alive(Relay))
    after
        exit(Relay, kill),
        close_all([PeerA, PeerB, RelayA, RelayB])
    end.

idle_timeout_closes_a_quiet_relay_test_() ->
    {"a relay with no traffic closes after one idle interval",
        {timeout, 30, fun idle_timeout_closes_a_quiet_relay/0}}.

idle_timeout_closes_a_quiet_relay() ->
    {RelayA, PeerA} = pair(),
    {RelayB, PeerB} = pair(),
    {Relay, Mon} = spawn_monitor(fun() -> i2per_proxy_relay:relay(RelayA, RelayB, 100) end),
    try
        receive
            {'DOWN', Mon, process, Relay, normal} -> ok
        after 2000 ->
            ?assert(false)
        end
    after
        close_all([PeerA, PeerB, RelayA, RelayB])
    end.

%% The shipped default is no idle timeout (i2pd imposes none), so a peer that
%% stays connected without sending anything is not cut. Resuming traffic after
%% that silence must still reach the other side.
relay_survives_silence_when_idle_timeout_is_disabled_test_() ->
    {"a default-config relay survives silence and resumes when traffic returns",
        {timeout, 30, fun relay_survives_silence/0}}.

relay_survives_silence() ->
    Saved = application:get_env(i2per_proxy, relay_idle_timeout_ms),
    application:unset_env(i2per_proxy, relay_idle_timeout_ms),
    ?assertEqual(infinity, i2per_proxy_config:relay_idle_timeout()),
    {RelayA, PeerA} = pair(),
    {RelayB, PeerB} = pair(),
    Relay = spawn(fun() -> i2per_proxy_relay:relay(RelayA, RelayB) end),
    try
        timer:sleep(300),
        ?assert(is_process_alive(Relay)),
        ok = gen_tcp:send(PeerA, <<"after-silence">>),
        {ok, <<"after-silence">>} = gen_tcp:recv(PeerB, 13, 2000)
    after
        exit(Relay, kill),
        close_all([PeerA, PeerB, RelayA, RelayB]),
        restore_env(relay_idle_timeout_ms, Saved)
    end.

pair() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, {_, Port}} = inet:sockname(LSock),
    {ok, Relay} = gen_tcp:connect(
        "127.0.0.1", Port, [binary, {packet, raw}, {active, false}], 5000
    ),
    {ok, Peer} = gen_tcp:accept(LSock, 5000),
    gen_tcp:close(LSock),
    {Relay, Peer}.

close_all(Socks) ->
    lists:foreach(fun(S) -> _ = gen_tcp:close(S) end, Socks).

restore_env(Key, {ok, Value}) ->
    application:set_env(i2per_proxy, Key, Value);
restore_env(Key, undefined) ->
    application:unset_env(i2per_proxy, Key).
