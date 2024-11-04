#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <rawsend.h>

#define MAX_IP_DATAGRAM_SIZE 65535

// Function Prototypes
static unsigned ip_header_checksum(const void *header);
static uint16_t udp_sum_calc(uint16_t len_udp, uint32_t src_addr, uint16_t src_port, uint32_t dest_addr, uint16_t dest_port, const void *buff);

int raw_send_from_to(int s, const void *msg, size_t msglen, struct sockaddr *saddr_generic, struct sockaddr *daddr_generic, int ttl, int flags) {
    struct sockaddr_in *saddr = (struct sockaddr_in *)saddr_generic;
    struct sockaddr_in *daddr = (struct sockaddr_in *)daddr_generic;

    struct sockaddr_in dest_a;
    struct ip ih;
    struct udphdr uh;
    struct msghdr mh;
    struct iovec iov[3];

    uh.uh_sport = saddr->sin_port;
    uh.uh_dport = daddr->sin_port;
    uh.uh_ulen = htons(msglen + sizeof(uh));
    uh.uh_sum = (flags & RAWSEND_COMPUTE_UDP_CHECKSUM) 
        ? udp_sum_calc(msglen, ntohl(saddr->sin_addr.s_addr), ntohs(saddr->sin_port), ntohl(daddr->sin_addr.s_addr), ntohs(daddr->sin_port), msg)
        : 0;

    int length = msglen + sizeof(uh) + sizeof(ih);

    ih.ip_hl = (sizeof(ih) >> 2);  // Header length
    ih.ip_v = 4;                    // IPv4
    ih.ip_tos = 0;
    ih.ip_len = htons(length);
    ih.ip_id = htons(0);
    ih.ip_off = 0;
    ih.ip_ttl = ttl;
    ih.ip_p = IPPROTO_UDP;
    ih.ip_sum = 0;                  // Initial checksum
    ih.ip_src = saddr->sin_addr;
    ih.ip_dst = daddr->sin_addr;
    ih.ip_sum = ip_header_checksum(&ih);  // Calculate checksum

    dest_a.sin_family = AF_INET;
    dest_a.sin_port = daddr->sin_port;
    dest_a.sin_addr = daddr->sin_addr;

    iov[0].iov_base = &ih;
    iov[0].iov_len = sizeof(ih);
    iov[1].iov_base = &uh;
    iov[1].iov_len = sizeof(uh);
    iov[2].iov_base = (char *)msg;
    iov[2].iov_len = msglen;

    memset(&mh, 0, sizeof(mh));
    mh.msg_name = &dest_a;
    mh.msg_namelen = sizeof(dest_a);
    mh.msg_iov = iov;
    mh.msg_iovlen = 3;

    if (sendmsg(s, &mh, 0) == -1) {
        perror("sendmsg failed");
        return -1;
    }
    return 0;
}

// Compute IP header checksum
static unsigned ip_header_checksum(const void *header) {
    unsigned long csum = 0;
    uint16_t *h = (uint16_t *)header;
    for (int i = 0; i < ((struct ip *)header)->ip_hl * 2; ++i) {
        csum += *h++;
    }
    while (csum >> 16) {
        csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum & 0xffff;
}

// UDP checksum calculation
static uint16_t udp_sum_calc(uint16_t len_udp, uint32_t src_addr, uint16_t src_port, uint32_t dest_addr, uint16_t dest_port, const void *buff) {
    uint32_t sum = 0;
    uint16_t prot_udp = IPPROTO_UDP;
    uint16_t udp_len = htons(len_udp + sizeof(struct udphdr));

    // Pseudo-header checksum
    sum += (src_addr >> 16) & 0xFFFF;
    sum += src_addr & 0xFFFF;
    sum += (dest_addr >> 16) & 0xFFFF;
    sum += dest_addr & 0xFFFF;
    sum += htons(prot_udp);
    sum += udp_len;

    // UDP header and payload
    sum += htons(src_port);
    sum += htons(dest_port);
    sum += udp_len;
    sum += 0;  // Placeholder for checksum field

    const uint16_t *payload = (const uint16_t *)buff;
    for (int i = 0; i < len_udp / 2; i++) {
        sum += *payload++;
    }
    if (len_udp % 2 == 1) {
        sum += *((const uint8_t *)payload);
    }

    // Wrap around and finalize
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}
