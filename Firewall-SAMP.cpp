#include <iostream>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <unordered_map>
#include <chrono>
#include <vector>

// Definir el puerto del servidor
#define SERVER_PORT 7777

// Definir el rango de puertos dinámicos permitidos
#define DYNAMIC_PORT_START 49152
#define DYNAMIC_PORT_END 65535

// Definir constantes para los queries 'c', 'd', 'x', 'r', 'i', 'p'
#define SAMP_HEADER 0x53414d50 // 'SAMP'
#define QUERY_C 0x63           // 'c'
#define QUERY_D 0x64           // 'd'
#define QUERY_X 0x78           // 'x'
#define QUERY_R 0x72           // 'r'
#define QUERY_I 0x69           // 'i'
#define QUERY_P 0x70           // 'p'

// Estructura para rastrear el estado de una conexión
struct Connection {
    int packet_count;
    std::chrono::steady_clock::time_point last_packet_time;
};

// Mapa para rastrear conexiones por IP de origen
std::unordered_map<std::string, Connection> connections;

// Función para analizar el paquete
void process_packet(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct udphdr *udph = (struct udphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
    unsigned char *data = buffer + iph->ihl * 4 + sizeof(struct ethhdr) + sizeof(struct udphdr);

    // Convertir la IP de origen a cadena
    struct in_addr ip_addr;
    ip_addr.s_addr = iph->saddr;
    std::string src_ip = inet_ntoa(ip_addr);

    // Verificar si el paquete es UDP y está destinado al puerto del servidor
    if (iph->protocol == IPPROTO_UDP && ntohs(udph->dest) == SERVER_PORT) {

        // Bloquear si el puerto de origen no está en el rango permitido
        if (ntohs(udph->source) < DYNAMIC_PORT_START || ntohs(udph->source) > DYNAMIC_PORT_END) {
            std::cout << "Paquete descartado: puerto de origen " << ntohs(udph->source) << " fuera del rango permitido." << std::endl;
            return;
        }

        uint32_t samp_header = *(uint32_t *)(data);
        unsigned char query_type = *(data + 7);

        // Verificar TTL y longitud del paquete
        if (iph->ttl == 128 && size >= 17 && size <= 604) {
            std::cout << "Paquete descartado: TTL = 128 y longitud entre 17 y 604 bytes." << std::endl;
            return;
        }

        // Verificar y descartar 'c', 'd' y 'x' queries
        if (samp_header == SAMP_HEADER && (query_type == QUERY_C || query_type == QUERY_D || query_type == QUERY_X)) {
            std::cout << "Paquete descartado: query " << query_type << std::endl;
            return;
        }

        // Límite de tasa para 'r', 'i' y 'p' queries
        auto current_time = std::chrono::steady_clock::now();
        if (connections.find(src_ip) == connections.end()) {
            connections[src_ip] = {1, current_time};
        } else {
            auto &connection = connections[src_ip];
            std::chrono::duration<double> elapsed = current_time - connection.last_packet_time;
            connection.last_packet_time = current_time;

            // Permitir solo 10 paquetes por segundo
            if (elapsed.count() < 1.0) {
                connection.packet_count++;
                if (connection.packet_count > 10) {
                    std::cout << "Paquete descartado: límite de tasa excedido para IP " << src_ip << std::endl;
                    return;
                }
            } else {
                connection.packet_count = 1;
            }
        }

        // Manejo de conexiones
        std::cout << "Paquete aceptado con límite de tasa: query " << query_type << " de IP " << src_ip << std::endl;
        return;
    }
}

int main() {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    unsigned char *buffer = new unsigned char[65536];

    // Crear un socket raw
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        std::cerr << "Error al crear el socket." << std::endl;
        return 1;
    }

    while (true) {
        // Recibir paquetes
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if (data_size < 0) {
            std::cerr << "Error al recibir datos." << std::endl;
            break;
        }

        // Procesar los paquetes recibidos
        process_packet(buffer, data_size);
    }

    close(sock_raw);
    delete[] buffer;
    return 0;
}
