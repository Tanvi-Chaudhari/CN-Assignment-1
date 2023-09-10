#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/types.h>

void packet_handler(const u_char *packet, int packet_len) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip_header->ip_hl << 2));

    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));
    printf("----------\n");
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t addr_len;
    char buffer[65536]; // Adjust the buffer size as needed

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    while (1) {
        int packet_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (packet_len < 0) {
            perror("recvfrom");
            return 1;
        }

        packet_handler(buffer, packet_len);
    }

    close(sockfd);
    return 0;
}
