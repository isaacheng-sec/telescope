#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "icmp.h"

int create_icmp_socket(void) { 
    
    int sock = socket(  // sets up kernel bookkeeping for a new endpoint and gives the handle
                        // sock is a local handle to a kernel data structure 
        AF_INET,        // ipv4 
        SOCK_RAW,       // raw socket, below transport abstraction
        IPPROTO_ICMP);  // only want ICMP payload, kernel builds IP header when sending
    if (sock < 0) {
        perror("socket"); // print socket + current errno variable associated
    }

    return sock;
}

struct icmphdr build_icmp_echo(uint16_t sequence, uint16_t id) {

  // building ICMP header
    struct icmphdr hdr;     // from <netinet/ip_icmp.h>, premade fields/sizes
    memset(&hdr, 0, sizeof(hdr));
    hdr.type = ICMP_ECHO;   // kind of message
    hdr.code = 0;           // subtypes, none here
    hdr.un.echo.id = id;     // ping ID masked to 16 bits
    hdr.un.echo.sequence = htons(sequence);   // incrementing counter
    hdr.checksum = checksum(&hdr, sizeof(hdr)); // compute after filling struct
    return hdr;

}


uint16_t checksum(void *data, int len) {
    uint16_t *buf = data; // reinterpret passed-in address as pointer to 16-bit chunks
    uint32_t sum = 0;

    // sum every 16 bit word
    while (len > 1) {
        sum += *buf++;
        len -= 2;       // 2 bytes each iteration
    }

    // handle leftover byte case (odd length)
    if (len == 1) {
        sum += *(uint8_t *)buf; // recast buf pointer to just 1 byte
    }

    // fold 32 bit sum down to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // take one's complement
    return (uint16_t)(~sum);

}

int receive_icmp_reply(int sock, char *buffer, size_t buflen,
                        struct sockaddr_in *from, socklen_t *fromlen) {

    // blocks until a packet arrives on the socket, then copies it to buffer
    ssize_t bytes = recvfrom(sock, buffer, buflen, 0, (struct sockaddr *)from, fromlen);

    if (bytes < 0) {
        perror("recvfrom");
        return -1;
    }

    return (int)bytes;

}

void print_icmp_reply(char *buffer, int bytes, struct sockaddr_in *from, struct timeval *sent_time, uint16_t expected_id) {

    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    int ip_header_len = ip_hdr->ihl * 4; // converting from 32-bit words to bytes

    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ip_header_len);

    // ignore anything that isn't a reply or addressed to this socket
    if (icmp_hdr->type != ICMP_ECHOREPLY) {
        return;
    }

    if (icmp_hdr->un.echo.id != expected_id) {
        return;
    }

    // time calculations for RTT
    struct timeval now;
    gettimeofday(&now, NULL);
    double rtt_ms = (now.tv_sec - sent_time->tv_sec) * 1000.0 +
                    (now.tv_usec - sent_time->tv_usec) / 1000.0;

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from->sin_addr, src_ip, sizeof(src_ip));

    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
        bytes - ip_header_len,
        src_ip,
        ntohs(icmp_hdr->un.echo.sequence),
        ip_hdr->ttl,
        rtt_ms);

}
