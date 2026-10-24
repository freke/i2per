-module(i2per_tun_ip).

-moduledoc """
Pure parsing helpers for the IP packets the TUN device hands us (epiq
`D3750BZ`).

The device owner (`m:i2per_tun_dev`) stays transport-agnostic and only counts;
this module turns a raw packet into something a flow table can key on. IPv4
only for 0.8.0 (Linux TUN, first cut); IPv6 is a follow-up alongside UDP.
""".

-export([parse/1, tcp_parse/1, udp_parse/1, flow_key/1]).

-dialyzer({no_underspecs, [flow_key/1]}).

-spec parse(binary()) -> {ok, map()} | {error, term()}.
parse(
    <<4:4, IHL:4, _Tos:8, TotalLen:16, _Id:16, _FlagsFrag:16, _Ttl:8, Proto:8, _Checksum:16,
        Src:4/binary, Dst:4/binary, Rest/binary>>
) ->
    HeaderBytes = IHL * 4,
    case byte_size(Rest) >= HeaderBytes - 20 of
        true ->
            Payload = binary:part(Rest, HeaderBytes - 20, byte_size(Rest) - (HeaderBytes - 20)),
            {ok, #{
                version => 4,
                ihl => IHL,
                protocol => Proto,
                total_len => TotalLen,
                src => bin_to_ip(Src),
                dst => bin_to_ip(Dst),
                payload => Payload
            }};
        false ->
            {error, truncated}
    end;
parse(_) ->
    {error, not_ipv4}.

-spec tcp_parse(binary()) -> {ok, map()} | {error, term()}.
tcp_parse(
    <<SrcPort:16, DstPort:16, _Seq:32, _Ack:32, Off:4, _Reserved:4, Flags:8, _Window:16,
        _Checksum:16, _Urgent:16, Rest/binary>>
) ->
    DataOffset = Off * 4,
    case byte_size(Rest) >= DataOffset - 20 of
        true ->
            Payload = binary:part(Rest, DataOffset - 20, byte_size(Rest) - (DataOffset - 20)),
            {ok, #{
                src_port => SrcPort,
                dst_port => DstPort,
                flags => Flags,
                payload => Payload
            }};
        false ->
            {error, truncated}
    end;
tcp_parse(_) ->
    {error, not_tcp}.

-spec udp_parse(binary()) -> {ok, map()} | {error, term()}.
udp_parse(<<SrcPort:16, DstPort:16, Len:16, _Checksum:16, Payload/binary>>) ->
    {ok, #{
        src_port => SrcPort,
        dst_port => DstPort,
        length => Len,
        payload => Payload
    }};
udp_parse(_) ->
    {error, not_udp}.

-spec flow_key(map()) -> term().
flow_key(#{src := Src, dst := Dst, protocol := 6} = Pkt) ->
    case tcp_parse(maps:get(payload, Pkt)) of
        {ok, #{src_port := SP, dst_port := DP}} ->
            {tcp, Src, Dst, SP, DP};
        _ ->
            {tcp, Src, Dst, 0, 0}
    end;
flow_key(#{src := Src, dst := Dst, protocol := 17} = Pkt) ->
    case udp_parse(maps:get(payload, Pkt)) of
        {ok, #{src_port := SP, dst_port := DP}} ->
            {udp, Src, Dst, SP, DP};
        _ ->
            {udp, Src, Dst, 0, 0}
    end;
flow_key(#{src := Src, dst := Dst, protocol := Proto}) ->
    {Proto, Src, Dst}.

bin_to_ip(<<A, B, C, D>>) ->
    {A, B, C, D}.
