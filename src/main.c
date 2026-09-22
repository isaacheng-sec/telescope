#include <stdio.h>      // printf, perror
#include <stdlib.h>     // exit, malloc
#include <netinet/ip_icmp.h>    // struct icmphdr, ICMP_ECHO, ICMP_ECHOREPLY

#include "icmp.h"
#include <arpa/inet.h>



int main(int argc, char** argv) {

    int sock = create_icmp_socket();
    if (sock < 0) {
        exit(1);
    }

    struct icmphdr hdr = build_icmp_echo(1);
    // next: sendto()

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.201", &dest.sin_addr);

    sendto(sock, &hdr, sizeof(hdr), 0, (struct sockaddr*)&dest, sizeof(dest));




    return 0;

}