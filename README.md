### Как использовать под С (действующая версия под windows)
gcc -o arp_parser arp_parser.c
./arp_parser



### Как использовать под erl
1> c(arp_parser).
{ok,arp_parser}

2> arp_parser:test().
ARP Parser Test
================

--- Тест 1: Парсинг тестового пакета ---
[OK] Успех

=== ARP Packet ===
Hardware type: 1 (0x0001)
Protocol type: 0x0800 (IPv4)
Hardware size: 6 байт
Protocol size: 4 байт
Opcode: REQUEST (1)
Sender MAC: 08:00:27:12:34:56
Sender IP: 192.168.1.1
Target MAC: 00:00:00:00:00:00
Target IP: 192.168.1.2
[OK] Формат Ethernet/IPv4
==================

Проверка по заданию:
Sender IP: 192.168.1.1 (должен быть 192.168.1.1) - [OK]
Target IP: 192.168.1.2 (должен быть 192.168.1.2) - [OK]

--- Тест 2: Недостаточная длина (20 байт) ---
[OK] Ожидаемая ошибка о недостаточной длине

... и так далее ...

Все тесты завершены
ok