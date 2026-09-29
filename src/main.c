#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

#include "icmp.h"



int main(int argc, char** argv) {


    uint16_t sequence = 1;
    int timeout_ms = 2000;
    
    int sock = create_icmp_socket();
    if (sock < 0) {
        exit(1);
    }

    uint16_t id = getpid() & 0xFFFF;
    struct icmphdr hdr = build_icmp_echo(1, id);
    

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.200", &dest.sin_addr);

    double sent_ms = now_ms();

    sendto(sock, &hdr, sizeof(hdr), 0, (struct sockaddr*)&dest, sizeof(dest));

    int r = wait_for_reply(sock, id, sequence, timeout_ms, sent_ms);
    if (r == 0) printf("Request timed out\n");

    return 0;

}