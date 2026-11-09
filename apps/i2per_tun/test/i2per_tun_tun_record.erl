-module(i2per_tun_tun_record).

%% Test seam: a TUN facade that records every write/2 call to a registered
%% sink process, so hermetic end-to-end tests can assert byte-for-byte
%% delivery on the TUN side without CAP_NET_ADMIN.

-export([version/0, open/1, read/1, write/2, arm/2, stop/1]).
-export([register_sink/1, unregister_sink/0, collect/2]).

version() -> <<"record">>.

open(_Name) -> {ok, record}.

read(_Dev) -> {error, eagain}.

write(_Dev, Packet) ->
    case whereis(i2per_tun_record_sink) of
        undefined ->
            ok;
        Pid ->
            Pid ! {tun_write, Packet},
            ok
    end.

arm(_Dev, _Pid) -> ok.

stop(_Dev) -> ok.

register_sink(Pid) ->
    unregister_sink(),
    register(i2per_tun_record_sink, Pid),
    ok.

unregister_sink() ->
    case whereis(i2per_tun_record_sink) of
        undefined ->
            ok;
        _Pid ->
            unregister(i2per_tun_record_sink),
            ok
    end.

%% Collect up to N tun_write messages within Timeout ms.
collect(N, Timeout) ->
    collect(N, Timeout, []).

collect(0, _Timeout, Acc) ->
    lists:reverse(Acc);
collect(N, Timeout, Acc) ->
    receive
        {tun_write, Packet} ->
            collect(N - 1, Timeout, [Packet | Acc])
    after Timeout ->
        lists:reverse(Acc)
    end.
