#ifndef ICMP_H
#define ICMP_H

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>


struct print_info {
    int icmp_bytes; // total portion minus IP header
    uint16_t sequence; // in network order
    double rtt_ms;
    struct in_addr src_addr; // in network order
    uint8_t ttl;

};


double now_ms(void);


// Creates a raw ICMP socket. Returns socket fd or -1 on failure
int create_icmp_socket(void);

// Builds an ICMP echo request header with the given sequence number
struct icmphdr build_icmp_echo(uint16_t sequence, uint16_t id);

// Calculates and returns the Internet checksum (RFC 1071)
uint16_t checksum(void *data, int len);

int block_for_icmp(int sock, char *buffer, size_t buflen,
                        struct sockaddr_in *from, socklen_t *fromlen);

int print_icmp_reply(char *buffer, int bytes, struct sockaddr_in *from,
                        double sent_ms, uint16_t expected_id, uint16_t expected_seq);
                    
int wait_for_reply(int sock, uint16_t id, uint16_t seq, int timeout_ms, double sent_ms);

void onlyprint_icmp(const struct print_info *print_info);


#endif