-module(i2per_tun_tun_fake).

%% Test seam: a TUN facade that never needs privileges, used by hermetic
%% i2per_tun_dev tests (epiq 091VYQC). Implements the same surface as
%% i2per_tun_tun but succeeds unconditionally.

-export([version/0, open/1, read/1, write/2, arm/2, stop/1]).

version() -> <<"fake">>.

open(_Name) -> {ok, fake}.

read(_Dev) -> {error, eagain}.

write(_Dev, _Packet) -> ok.

arm(_Dev, _Pid) -> ok.

stop(_Dev) -> ok.