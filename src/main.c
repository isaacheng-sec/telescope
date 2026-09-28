#include <stdio.h>      // printf, perror
#include <stdlib.h>     // exit, malloc
#include <netinet/ip_icmp.h>    // struct icmphdr, ICMP_ECHO, ICMP_ECHOREPLY

#include "icmp.h"
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>



int main(int argc, char** argv) {

    int sock = create_icmp_socket();
    if (sock < 0) {
        exit(1);
    }

    uint16_t id = getpid() & 0xFFFF;
    struct icmphdr hdr = build_icmp_echo(1, id);
    

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.201", &dest.sin_addr);

    struct timeval sent_time;
    gettimeofday(&sent_time, NULL);

    sendto(sock, &hdr, sizeof(hdr), 0, (struct sockaddr*)&dest, sizeof(dest));

    char recv_buf[1024];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    int bytes = receive_icmp_reply(sock, recv_buf, sizeof(recv_buf), &from, &fromlen);
    if (bytes > 0) {
        print_icmp_reply(recv_buf, bytes, &from, &sent_time, id);
    }


    return 0;

}