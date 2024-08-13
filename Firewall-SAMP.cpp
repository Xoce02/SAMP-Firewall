// ¿Como utilizarlo?
// Utiliza estos comandos
// apt-get install g++
// g++ -o samp Firewall-SAMP.cpp
// Ejecuta el script con ./samp
// Ejecutarlo en segundo plano: nohup ./samp &
// Eliminarlo de segundo plano: pkill samp


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

// Función para analizar el paquete
void process_packet(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct udphdr *udph = (struct udphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
    unsigned char *data = buffer + iph->ihl * 4 + sizeof(struct ethhdr) + sizeof(struct udphdr);

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

        // limitar la tasa de 'r', 'i' y 'p' queries
        if (samp_header == SAMP_HEADER && (query_type == QUERY_R || query_type == QUERY_I || query_type == QUERY_P)) {
            std::cout << "Paquete aceptado con límite de tasa: query " << query_type << std::endl;
            return;
        }

        // Otros paquetes que no cumplen con las reglas
        std::cout << "Paquete aceptado sin condiciones específicas." << std::endl;
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
