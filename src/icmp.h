#ifndef ICMP_H
#define ICMP_H

#include <netinet/ip_icmp.h>


// Creates a raw ICMP socket. Returns socket fd or -1 on failure
int create_icmp_socket(void);

// Builds an ICMP echo request header with the given sequence number
struct icmphdr build_icmp_echo(uint16_t sequence);

// Calculates and returns the Internet checksum (RFC 1071)
uint16_t checksum(void *data, int len);



#endif