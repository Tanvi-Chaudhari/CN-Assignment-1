#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h> 
#include <string.h>     
#include <stdbool.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

    // if this packet contains TCP data
    if (pkthdr->caplen >= 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)) {
        // To get pointer to the start of TCP payload
        const u_char *payload = packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);
        int payload_length = pkthdr->caplen - (14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)); 
        char payload_string[payload_length + 1];
        memcpy(payload_string, payload, payload_length);
        payload_string[payload_length] = '\0';

        // For checking keyword "Flag"
        if (strstr(payload_string, "Flag") != NULL) {
            printf("\n%s\n", payload_string);
            
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
