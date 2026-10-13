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
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <string.h>

#include "icmp.h"

// returns the current time, measured in milliseconds (for comparing)
double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// sets up kernel bookkeeping for a new endpoint. Returns the handle (file descriptor)
int create_icmp_socket(void) { 
    
    int sock = socket(
                        // sock is a local handle to a kernel data structure 
        AF_INET,        // ipv4 
        SOCK_RAW,       // raw socket, below transport abstraction
        IPPROTO_ICMP);  // only want ICMP payload, kernel builds IP header when sending
    if (sock < 0) {
        perror("socket"); // print socket + current errno variable associated
    }

    return sock;
}

// builds ICMP echo header for a given sequence and id number
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

// calculate the checksum of the packet data. Returns the 16-bit checksum value
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

// blocks until a packet arrives on the socket, then copies it to buffer
int receive_icmp(int sock, char *buffer, size_t buflen,
                        struct sockaddr_in *from, socklen_t *fromlen) {

    ssize_t bytes = recvfrom(sock, buffer, buflen, 0, (struct sockaddr *)from, fromlen);

    if (bytes < 0) {
        perror("recvfrom");
        return -1;
    }

    return (int)bytes;

}


// poll socket until data is ready, then receive and parse. Returns 1 for a successful reply, 0 for a timeout
int wait_for_reply(int sock, uint16_t id, uint16_t seq, uint32_t expected_addr,
                    int timeout_ms, double sent_ms, struct print_info *out) {
    char buf[1024];
    struct sockaddr_in from;
    double deadline = sent_ms + timeout_ms;

    for (;;) {
        double remaining = deadline - now_ms();
        if (remaining <= 0) {
            return 0;       // deadline passed
        }
        
        struct pollfd pfd = { .fd = sock, .events = POLLIN }; // polling request
        int ready = poll(&pfd, 1, (int)remaining + 1); // wait for data or timeout (remaining time max)

        if (ready == 0) return 0;       // poll timed out
        if (ready < 0) {
            if (errno != EINTR) perror("poll");
            return -1;          // signal or real error
        }

        // socket is readable, so recvfrom() won't block
        socklen_t fromlen = sizeof(from);
        int bytes = receive_icmp(sock, buf, sizeof(buf), &from, &fromlen);
        double recv_ms = now_ms();
        if (bytes < 0) return -1;

        // ignore any packets that don't pass parsing
        if (parse_icmp_header(buf, bytes, id, seq, expected_addr, out)) {
           out->rtt_ms = recv_ms - sent_ms;
            return 1;
        }
    }
}

void print_icmp(const struct print_info *print_struct) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &print_struct->src_addr, src_ip, sizeof(src_ip));

    printf("Response! %d bytes from %s: seq=%d ttl=%d time=%.2f ms\n",
        print_struct->icmp_bytes,
        src_ip,
        ntohs(print_struct->sequence),
        print_struct->ttl,
        print_struct->rtt_ms);

}

// check fields of ICMP header and fill in info struct if it passes
int parse_icmp_header(const char *buffer, int bytes, uint16_t expected_id, uint16_t expected_seq, uint32_t expected_addr, struct print_info *out) {
    if (bytes < (int)sizeof(struct iphdr)) {
        return 0;       // check if there's enough bytes for an IP header to be interpreted
    }
    // safe to read IP header and ihl field
    const struct iphdr *ip_hdr = (struct iphdr *)buffer;
    int ip_header_len = ip_hdr->ihl * 4; // converting from 32-bit words to bytes

    // check if the header line is valid and if an icmp header exists after it
    if (ip_hdr->ihl < 5 || bytes < ip_header_len + (int)sizeof(struct icmphdr)) {
        return 0;
    }

    // check if source address matches what was expected
    if (ip_hdr->saddr != expected_addr) {
        return 0;
    }

    // safe to read ICMP header
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ip_header_len);

    // ignore anything that isn't a reply or addressed to this socket
    if (icmp_hdr->type != ICMP_ECHOREPLY) {
        return 0;
    }

    if (icmp_hdr->un.echo.id != expected_id) {
        return 0;
    }
    // ignore packets with improper sequence number
    if (ntohs(icmp_hdr->un.echo.sequence) != expected_seq) {
        return 0;
    }

    out->icmp_bytes = bytes - ip_header_len;
    out->sequence = icmp_hdr->un.echo.sequence;
    out->ttl = ip_hdr->ttl;
    out->src_addr.s_addr = ip_hdr->saddr;

    return 1;
}

// full "ping a host" function. returns 1 for alive, 0 for no response, fills in print_info on success
int ping_host(int sock, uint16_t id, uint16_t sequence, const struct sockaddr_in *dest_addr, int timeout_ms, struct print_info *out) {
    
    struct icmphdr hdr = build_icmp_echo(sequence, id);
    uint32_t target_addr = dest_addr->sin_addr.s_addr; // struct sockaddr_in -> struct sin_addr -> field s_addr
    
    double sent_ms = now_ms();  // for rtt calculation
    int sent_status = sendto(sock, &hdr, sizeof(hdr), 0, (const struct sockaddr *) dest_addr, sizeof(struct sockaddr_in));
   
    if (sent_status == -1) {
         perror("sendto");
         return -1;
    }

    int r = wait_for_reply(sock, id, sequence, target_addr, timeout_ms, sent_ms, out);
    return r;
}
