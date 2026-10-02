-module(i2p_log_tests_collector).

-moduledoc """
A `logger` handler that forwards every log event it receives to one process.

The log-capture counterpart to `m:i2p_events_tests_collector`, and built the same
way: the handler is the observer, and `m:i2p_ct_helpers:log_lines_from/1` is what
puts a barrier after the work under test so the assertion has something to wait
on.

Two OTP details are load-bearing and were established by checking this OTP rather
than by writing to the documentation's shape:

- A handler in OTP 28 exports **`log/2`**, not the `gen_event` callbacks. The
  `gen_event` shape (`init/1`, `handle_event/2`) is rejected with
  `{invalid_handler, {function_not_exported, ...}}`, and adding the *optional*
  `adding_handler/1` returning bare `ok` crashes `logger_server` outright. So this
  module exports `log/2` and nothing else.
- `logger:add_handler/3` rejects a bare term as its config with
  `{invalid_config, _}`, so the destination process travels as
  `#{config => Pid}` and arrives as the second argument of `log/2`.

Delivered messages are `#{level := atom(), msg := {Format, Args}}`, which is what
`logger`'s own formatters consume, so a test can render a line without this module
knowing anything about formatting.
""".

-export([start/1, stop/1, log/2]).

-doc """
Attach the collector and start forwarding to `Owner`.

Output: `{ok, HandlerId}` — a term safe to pass back to `f:stop/1` and to
`logger:remove_handler/1` — or `{error, Reason}` if `logger` refused.
""".
-spec start(pid()) -> {ok, logger:handler_id()} | {error, term()}.
start(Owner) ->
    Id = list_to_atom("i2p_log_capture_" ++ integer_to_list(erlang:unique_integer([positive]))),
    case logger:add_handler(Id, ?MODULE, #{config => Owner}) of
        ok -> {ok, Id};
        {error, _} = Refused -> Refused
    end.

-doc """
Detach the collector.

Input: the `{ok, HandlerId}` from `f:start/1`. Output: `ok`.

Synchronous, which is what makes it safe in a `try`'s `after`: by the time it
returns the handler's process has stopped and no further line can arrive, so a
test cannot be handed a message by a handler it has already torn down.
""".
-spec stop({ok, logger:handler_id()}) -> ok.
stop({ok, Id}) ->
    _ = logger:remove_handler(Id),
    ok.

-doc "`logger` handler callback: forward one log event to the collector's process.".
-spec log(#{level := logger:level(), msg := {io:format(), list()}}, map()) -> ok.
log(LogEvent, #{config := Owner}) ->
    Owner ! {log_line, LogEvent},
    ok.
