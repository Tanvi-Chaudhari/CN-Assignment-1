#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h> 
#include <string.h>     


void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

    // Check if this packet contains TCP data
    if (pkthdr->caplen >= 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)) {
        // Get a pointer to the start of TCP payload
        const u_char *payload = packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);
        int payload_length = pkthdr->caplen - (14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));

        // Check if the TCP checksum matches 0xf436
        if (ntohs(tcp_header->th_sum) == 0xf436) {
            printf("TCP Packet with Checksum 0xf436 Found:\n");
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));
            printf("Payload Length: %d bytes\n", payload_length);

            // Assuming the payload is HTTP data, try to find HTTP headers
            const char *http_request = "HTTP/1.1";
            const char *http_response = "HTTP/1.1";

            if (strstr((const char *)payload, http_request) || strstr((const char *)payload, http_response)) {
                printf("HTTP Request or Response:\n");
                printf("%s\n", (const char *)payload);
            } else {
                printf("Payload:\n");
                for (int i = 0; i < payload_length; i++) {
                    printf("%02X ", payload[i]);
                    if (i % 16 == 15 || i == payload_length - 1)
                        printf("\n");
                }
            }
     
        }
    }
}




int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open interface '%s': %s\n", argv[1], errbuf);
        return 2;
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
        return 2;
    }

    pcap_close(handle);
    return 0;
}
