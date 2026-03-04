#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

struct arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hsize;
    uint8_t psize;
    uint16_t op;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
};

uint8_t test_arp_packet[] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0x08, 0x00, 0x27, 0x12, 0x34, 0x56, 0xC0, 0xA8,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x02
};

uint16_t ntoh_16(const uint8_t *data) {
    return (data[0] << 8) | data[1];
}

int parse_arp(const uint8_t *data, size_t len, struct arp_packet *packet) {
    if (data == NULL || packet == NULL) {
        return -1;
    }
    
    if (len < 28) {
        return -2;
    }
    
    packet->htype = ntoh_16(data);
    packet->ptype = ntoh_16(data + 2);
    packet->hsize = data[4];
    packet->psize = data[5];
    packet->op = ntoh_16(data + 6);
    
    memcpy(packet->sha, data + 8, 6);
    memcpy(packet->spa, data + 14, 4);
    memcpy(packet->tha, data + 18, 6);
    memcpy(packet->tpa, data + 24, 4);
    
    if (packet->hsize != 6 || packet->psize != 4) {
        return -3;
    }
    
    return 0;
}

void mac_to_string(const uint8_t *mac, char *buffer) {
    sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void ip_to_string(const uint8_t *ip, char *buffer) {
    sprintf(buffer, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

const char* opcode_to_string(uint16_t op) {
    switch(op) {
        case 1: return "REQUEST (1)";
        case 2: return "REPLY (2)";
        default: return "UNKNOWN";
    }
}

void print_arp(const struct arp_packet *packet) {
    if (packet == NULL) {
        printf("Ошибка: NULL указатель на пакет\n");
        return;
    }
    
    char mac_buffer[18];
    char ip_buffer[16];
    
    printf("\n=== ARP Packet ===\n");
    printf("Hardware type: %u (0x%04x)\n", packet->htype, packet->htype);
    printf("Protocol type: 0x%04x", packet->ptype);
    
    if (packet->ptype == 0x0800) {
        printf(" (IPv4)");
    }
    printf("\n");
    
    printf("Hardware size: %u байт\n", packet->hsize);
    printf("Protocol size: %u байт\n", packet->psize);
    printf("Opcode: %s\n", opcode_to_string(packet->op));
    
    mac_to_string(packet->sha, mac_buffer);
    printf("Sender MAC: %s\n", mac_buffer);
    
    ip_to_string(packet->spa, ip_buffer);
    printf("Sender IP: %s\n", ip_buffer);
    
    mac_to_string(packet->tha, mac_buffer);
    printf("Target MAC: %s\n", mac_buffer);
    
    ip_to_string(packet->tpa, ip_buffer);
    printf("Target IP: %s\n", ip_buffer);
    
    if (packet->hsize == 6 && packet->psize == 4) {
        printf("[OK] Формат Ethernet/IPv4\n");
    }
    printf("==================\n");
}

void run_tests() {
    printf("\n=== ЗАПУСК ТЕСТОВ ===\n");
    
    // Тест 1: Нормальный пакет
    printf("\nТест 1: Нормальный пакет\n");
    struct arp_packet packet1;
    int result = parse_arp(test_arp_packet, sizeof(test_arp_packet), &packet1);
    if (result == 0) {
        printf("[OK] Успех\n");
        print_arp(&packet1);
    } else {
        printf("[ERROR] Ошибка: код %d\n", result);
    }
    
    // Тест 2: NULL указатель
    printf("\nТест 2: NULL указатель на данные\n");
    result = parse_arp(NULL, 28, &packet1);
    printf("Ожидаемый код: -1, Полученный код: %d - %s\n", 
           result, result == -1 ? "[OK]" : "[ERROR]");
    
    // Тест 3: Недостаточная длина
    printf("\nТест 3: Недостаточная длина (20 байт)\n");
    result = parse_arp(test_arp_packet, 20, &packet1);
    printf("Ожидаемый код: -2, Полученный код: %d - %s\n", 
           result, result == -2 ? "[OK]" : "[ERROR]");
    
    // Тест 4: Создание своего ARP-ответа
    printf("\nТест 4: Создание своего ARP-ответа\n");
    uint8_t custom_packet[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xc0, 0xa8, 0x01, 0x64,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0xc0, 0xa8, 0x01, 0x01
    };
    
    struct arp_packet packet2;
    result = parse_arp(custom_packet, sizeof(custom_packet), &packet2);
    if (result == 0) {
        printf("[OK] Успех\n");
        print_arp(&packet2);
    } else {
        printf("[ERROR] Ошибка: код %d\n", result);
    }
}

int main() {
    // Устанавливаем кодировку UTF-8 для консоли Windows
    SetConsoleOutputCP(CP_UTF8);
    
    printf("ARP Parser Demo\n");
    printf("===============\n");
    
    // Разбор тестового пакета
    printf("\n--- Разбор тестового пакета из задания ---\n");
    struct arp_packet packet;
    int result = parse_arp(test_arp_packet, sizeof(test_arp_packet), &packet);
    
    if (result == 0) {
        print_arp(&packet);
        
        // Проверка соответствия примеру
        printf("\nПроверка по заданию:\n");
        char ip_buffer[16];
        ip_to_string(packet.spa, ip_buffer);
        printf("Sender IP: %s (должен быть 192.168.1.1) - %s\n", 
               ip_buffer, strcmp(ip_buffer, "192.168.1.1") == 0 ? "[OK]" : "[ERROR]");
        
        ip_to_string(packet.tpa, ip_buffer);
        printf("Target IP: %s (должен быть 192.168.1.2) - %s\n", 
               ip_buffer, strcmp(ip_buffer, "192.168.1.2") == 0 ? "[OK]" : "[ERROR]");
    } else {
        printf("Ошибка парсинга: код %d\n", result);
    }
    
    // Запуск дополнительных тестов
    run_tests();
    
    printf("\nНажмите Enter для выхода...");
    getchar();
    
    return 0;
}