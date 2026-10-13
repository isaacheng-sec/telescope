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

int main() {


    int sock = create_icmp_socket();
    if (sock < 0) { exit(1); }
    
    uint16_t id = getpid() & 0xFFFF;
    struct print_info icmp_info;
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    memset(&icmp_info, 0, sizeof(icmp_info));

    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.201", &dest.sin_addr);

    for (uint16_t sequence = 1; sequence <= MAX_TRIES; sequence++) {
        double sent_ms = now_ms();
        int r = ping_host(sock, id, sequence, &dest, TIMEOUT_MS, &icmp_info);
        if (r == 0) printf("Request timed out\n");
        if (r == 1) print_icmp(&icmp_info);
        if (r == -1) {
        // TODO: error checking
        return -1;
        }

        double elapsed = now_ms() - sent_ms;    // for interval scheduling
        double remaining_time = INTERVAL_MS - (elapsed);   
        if (remaining_time > 0 && sequence != MAX_TRIES) {
            usleep((useconds_t)remaining_time * 1000);
        }
    }

    close(sock);

    return 0;

}