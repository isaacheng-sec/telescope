#ifndef ICMP_H
#define ICMP_H

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>


// Creates a raw ICMP socket. Returns socket fd or -1 on failure
int create_icmp_socket(void);

// Builds an ICMP echo request header with the given sequence number
struct icmphdr build_icmp_echo(uint16_t sequence, uint16_t id);

// Calculates and returns the Internet checksum (RFC 1071)
uint16_t checksum(void *data, int len);

int receive_icmp_reply(int sock, char *buffer, size_t buflen,
                        struct sockaddr_in *from, socklen_t *fromlen);

void print_icmp_reply(char *buffer, int bytes, struct sockaddr_in *from,
                        struct timeval *sent_time, uint16_t expected_id);
                    



#endif