#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "icmp.h"

int create_icmp_socket(void) { 
    
    int sock = socket(  // sets up kernel bookkeeping for a new endpoint and gives the handle
                        // sock is a local handle to a kernel data structure 
        AF_INET,        // ipv4 
        SOCK_RAW,       // raw socket, below transport abstraction
        IPPROTO_ICMP);  // only want ICMP payload, kernel builds IP header when sending
    if (sock < 0) {
        perror("socket"); // print socket + current errno variable associated
        exit(1);
    }

    return sock;
}

struct icmphdr build_icmp_echo(uint16_t sequence) {

  // building ICMP header
    struct icmphdr hdr;     // from <netinet/ip_icmp.h>, premade fields/sizes
    memset(&hdr, 0, sizeof(hdr));
    hdr.type = ICMP_ECHO;   // kind of message
    hdr.code = 0;           // subtypes, none here
    hdr.un.echo.id = getpid() & 0xFFFF;     // ping ID masked to 16 bits
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