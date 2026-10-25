-module(i2per_proxy_listener_tests).

-include_lib("eunit/include/eunit.hrl").

%% An accept error that is neither `timeout` nor `closed` -- `emfile` on a full
%% fd table, `econnaborted` from a client that dropped before it was accepted --
%% used to fall through `handle_info/2` as a `case_clause` crash, and five of
%% those in ten seconds took `i2per_proxy` down with the listener (YBTMCNP).
%%
%% A connected socket is not a listening socket, so `gen_tcp:accept/2` answers
%% `{error, einval}`. That is the same shape without having to exhaust the fd
%% table to produce it.
accept_error_keeps_listener_alive_test() ->
    {ok, Listener} = i2per_proxy_listener:start_link(#{protocol => http, port => 0}),
    BoundPort = i2per_proxy_listener:port(Listener),
    %% `#state.lsock` is element 2 of the record tuple. The fixture replaces it
    %% rather than reaching into the live listening socket's fd, which would
    %% need privileged fd exhaustion to fail any other way.
    State = sys:get_state(Listener),
    LSock = element(2, State),
    {BadSock, ClientSock} = connected_socket(),
    Swapped = sys:replace_state(Listener, fun(S) -> setelement(2, S, BadSock) end),
    ?assertEqual(BadSock, element(2, Swapped)),
    try
        Listener ! accept,
        %% `port/1` is a gen_server call, answered only if the accept message was
        %% handled without crashing. Being a call, it also puts a later message in
        %% the mailbox, so there is no sleep here to guess at.
        ?assertEqual(BoundPort, i2per_proxy_listener:port(Listener)),
        ?assert(is_process_alive(Listener))
    after
        stop(Listener, LSock, BadSock, ClientSock)
    end.

%% The accepted end of a TCP connection: `gen_tcp:accept/2` on it is
%% `{error, einval}`.
connected_socket() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(LSock),
    {ok, ClientSock} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}], 5000),
    {ok, AcceptedSock} = gen_tcp:accept(LSock, 5000),
    gen_tcp:close(LSock),
    {AcceptedSock, ClientSock}.

%% `terminate/2` closes the swapped-in fixture socket, so the real listening
%% socket is closed here or the bound port stays open for the rest of the run.
stop(Listener, LSock, BadSock, ClientSock) ->
    _ = catch i2per_proxy_listener:stop(Listener),
    gen_tcp:close(LSock),
    gen_tcp:close(BadSock),
    gen_tcp:close(ClientSock).
