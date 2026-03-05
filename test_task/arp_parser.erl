-module(arp_parser).
-export([parse/1, print_arp/1, test/0]).

-record(arp_packet, {
    htype,      % hardware type (2 байта)
    ptype,      % protocol type (2 байта)
    hsize,      % hardware size (1 байт)
    psize,      % protocol size (1 байт)
    op,         % opcode (2 байта)
    sha,        % sender MAC (6 байт)
    spa,        % sender IP (4 байта)
    tha,        % target MAC (6 байт)
    tpa         % target IP (4 байта)
}).

% Тестовый пакет из задания
-define(TEST_PACKET, <<
    16#00, 16#01, 16#08, 16#00, 16#06, 16#04, 16#00, 16#01,
    16#08, 16#00, 16#27, 16#12, 16#34, 16#56, 16#C0, 16#A8,
    16#01, 16#01, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
    16#C0, 16#A8, 16#01, 16#02
>>).

% Основная функция парсинга
parse(Binary) when is_binary(Binary) ->
    case byte_size(Binary) of
        28 ->
            parse_arp_packet(Binary);
        Size when Size < 28 ->
            {error, {insufficient_data, Size, "Need 28 bytes"}};
        Size when Size > 28 ->
            {error, {too_much_data, Size, "Expected 28 bytes"}}
    end;
parse(_) ->
    {error, invalid_data_type}.

% Внутренняя функция для разбора 28-байтного пакета
parse_arp_packet(<<
    HType:16,           % 2 байта - hardware type
    PType:16,           % 2 байта - protocol type
    HSize:8,            % 1 байт - hardware size
    PSize:8,            % 1 байт - protocol size
    Op:16,              % 2 байта - opcode
    SHa:6/binary,       % 6 байт - sender MAC
    SPa:4/binary,       % 4 байта - sender IP
    THa:6/binary,       % 6 байт - target MAC
    TPa:4/binary        % 4 байта - target IP
>>) ->
    % Проверка корректности размеров
    case {HSize, PSize} of
        {6, 4} ->
            % Все хорошо - возвращаем заполненный record
            #arp_packet{
                htype = HType,
                ptype = PType,
                hsize = HSize,
                psize = PSize,
                op = Op,
                sha = SHa,
                spa = SPa,
                tha = THa,
                tpa = TPa
            };
        _ ->
            {error, {invalid_address_sizes, HSize, PSize}}
    end.

% Функция для форматирования MAC-адреса
format_mac(<<A, B, C, D, E, F>>) ->
    lists:flatten(io_lib:format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B",
                                [A, B, C, D, E, F])).

% Функция для форматирования IP-адреса
format_ip(<<A, B, C, D>>) ->
    lists:flatten(io_lib:format("~B.~B.~B.~B", [A, B, C, D])).

% Функция для получения строки типа операции
opcode_to_string(1) -> "REQUEST (1)";
opcode_to_string(2) -> "REPLY (2)";
opcode_to_string(Op) -> lists:flatten(io_lib:format("UNKNOWN (~B)", [Op])).

% Функция вывода record
print_arp(#arp_packet{
    htype = HType,
    ptype = PType,
    hsize = HSize,
    psize = PSize,
    op = Op,
    sha = SHa,
    spa = SPa,
    tha = THa,
    tpa = TPa
}) ->
    io:format("~n=== ARP Packet ===~n"),
    io:format("Hardware type: ~B (0x~4.16.0B)~n", [HType, HType]),
    
    ProtocolStr = case PType of
        16#0800 -> " (IPv4)";
        _ -> ""
    end,
    io:format("Protocol type: 0x~4.16.0B~s~n", [PType, ProtocolStr]),
    
    io:format("Hardware size: ~B байт~n", [HSize]),
    io:format("Protocol size: ~B байт~n", [PSize]),
    io:format("Opcode: ~s~n", [opcode_to_string(Op)]),
    
    io:format("Sender MAC: ~s~n", [format_mac(SHa)]),
    io:format("Sender IP: ~s~n", [format_ip(SPa)]),
    io:format("Target MAC: ~s~n", [format_mac(THa)]),
    io:format("Target IP: ~s~n", [format_ip(TPa)]),
    
    case {HSize, PSize} of
        {6, 4} -> io:format("[OK] Формат Ethernet/IPv4~n");
        _ -> ok
    end,
    io:format("==================~n").

% Функция для тестирования нормального пакета
test_normal_packet() ->
    io:format("~n--- Тест 1: Парсинг тестового пакета ---~n"),
    case parse(?TEST_PACKET) of
        {error, Reason} ->
            io:format("[ERROR] Ошибка: ~p~n", [Reason]);
        Packet when is_record(Packet, arp_packet) ->
            io:format("[OK] Успех~n"),
            print_arp(Packet),
            
            % Проверка соответствия примеру
            io:format("~nПроверка по заданию:~n"),
            #arp_packet{spa = SPa, tpa = TPa} = Packet,
            
            SenderIP = format_ip(SPa),
            TargetIP = format_ip(TPa),
            
            io:format("Sender IP: ~s (должен быть 192.168.1.1) - ~s~n", 
                     [SenderIP, case SenderIP of "192.168.1.1" -> "[OK]"; _ -> "[ERROR]" end]),
            io:format("Target IP: ~s (должен быть 192.168.1.2) - ~s~n", 
                     [TargetIP, case TargetIP of "192.168.1.2" -> "[OK]"; _ -> "[ERROR]" end])
    end.

% Тест недостаточной длины
test_insufficient_length() ->
    io:format("~n--- Тест 2: Недостаточная длина (20 байт) ---~n"),
    SmallPacket = binary:part(?TEST_PACKET, 0, 20),
    case parse(SmallPacket) of
        {error, {insufficient_data, 20, _}} ->
            io:format("[OK] Ожидаемая ошибка о недостаточной длине~n");
        Other ->
            io:format("[ERROR] Неожиданный результат: ~p~n", [Other])
    end.

% Тест слишком большой длины
test_too_big_length() ->
    io:format("~n--- Тест 3: Слишком большая длина (32 байта) ---~n"),
    BigPacket = <<?TEST_PACKET/binary, 0,0,0,0>>,
    case parse(BigPacket) of
        {error, {too_much_data, 32, _}} ->
            io:format("[OK] Ожидаемая ошибка о слишком большой длине~n");
        Other ->
            io:format("[ERROR] Неожиданный результат: ~p~n", [Other])
    end.

% Тест неверного типа данных
test_invalid_type() ->
    io:format("~n--- Тест 4: Неверный тип данных (не бинарные) ---~n"),
    case parse(not_binary) of
        {error, invalid_data_type} ->
            io:format("[OK] Ожидаемая ошибка о неверном типе данных~n");
        Other ->
            io:format("[ERROR] Неожиданный результат: ~p~n", [Other])
    end.

% Тест ARP-ответа
test_arp_reply() ->
    io:format("~n--- Тест 5: Парсинг ARP-ответа ---~n"),
    ReplyPacket = <<
        16#00, 16#01, 16#08, 16#00, 16#06, 16#04, 16#00, 16#02,  % REPLY
        16#aa, 16#bb, 16#cc, 16#dd, 16#ee, 16#ff,                  % MAC: aa:bb:cc:dd:ee:ff
        16#c0, 16#a8, 16#01, 16#64,                                % IP: 192.168.1.100
        16#11, 16#22, 16#33, 16#44, 16#55, 16#66,                  % MAC: 11:22:33:44:55:66
        16#c0, 16#a8, 16#01, 16#01                                 % IP: 192.168.1.1
    >>,
    case parse(ReplyPacket) of
        {error, Reason} ->
            io:format("[ERROR] Ошибка: ~p~n", [Reason]);
        Packet when is_record(Packet, arp_packet) ->
            io:format("[OK] Успех~n"),
            print_arp(Packet)
    end.

% Тест неверных размеров адресов
test_invalid_sizes() ->
    io:format("~n--- Тест 6: Неверные размеры адресов ---~n"),
    BadSizePacket = <<
        16#00, 16#01, 16#08, 16#00, 16#08, 16#08, 16#00, 16#01,  % hsize=8, psize=8 (неправильно)
        16#08, 16#00, 16#27, 16#12, 16#34, 16#56, 16#C0, 16#A8,
        16#01, 16#01, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
        16#C0, 16#A8, 16#01, 16#02
    >>,
    case parse(BadSizePacket) of
        {error, {invalid_address_sizes, 8, 8}} ->
            io:format("[OK] Ожидаемая ошибка о неверных размерах адресов~n");
        Other ->
            io:format("[ERROR] Неожиданный результат: ~p~n", [Other])
    end.

% Основная тестовая функция
test() ->
    io:format("ARP Parser Test~n"),
    io:format("================~n"),
    
    test_normal_packet(),
    test_insufficient_length(),
    test_too_big_length(),
    test_invalid_type(),
    test_arp_reply(),
    test_invalid_sizes(),
    
    io:format("~nВсе тесты завершены~n"),
    ok.