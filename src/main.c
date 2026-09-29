#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

#include "icmp.h"

#define INTERVAL_MS 1000
#define TIMEOUT_MS 2000
#define MAX_TRIES 10

int main(int argc, char** argv) {


    int sock = create_icmp_socket();
    if (sock < 0) { exit(1); }
    uint16_t id = getpid() & 0xFFFF;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.201", &dest.sin_addr);

    for (uint16_t sequence = 1; sequence <= MAX_TRIES; sequence++) {
    
        struct icmphdr hdr = build_icmp_echo(sequence, id);
        double sent_ms = now_ms();

        sendto(sock, &hdr, sizeof(hdr), 0, (struct sockaddr*)&dest, sizeof(dest));

        int r = wait_for_reply(sock, id, sequence, TIMEOUT_MS, sent_ms);
        if (r == 0) printf("Request timed out\n");

        double elapsed = now_ms() - sent_ms;
        double remaining_time = INTERVAL_MS - (elapsed);
        
        if (remaining_time > 0 && sequence != MAX_TRIES) {
            usleep((useconds_t)remaining_time * 1000);
        }
    }
    close(sock);

    return 0;

}