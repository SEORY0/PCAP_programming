#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethHeader {
    u_char  etherDstMac[6];  // Destination MAC
    u_char  etherSrcMac[6];  // Source MAC
    u_short etherType;       // Ethernet type
};

/* IP Header */
struct ipHeader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

/* TCP Header */
struct tcpHeader {
    u_short tcpSrcPort;
    u_short tcpDstPort;
    u_int   tcpSeq;
    u_int   tcpAck;
    u_char  tcpOffset:4;
    u_char  tcpReserved:4;
    u_char  tcpFlags;
    u_short tcpWindow;
    u_short tcpChecksum;
    u_short tcpUrgent;
};

/* 패킷 분석 및 출력 함수 */
void packetCapture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->len < sizeof(struct ethHeader)) return;

    struct ethHeader *eth = (struct ethHeader *)packet;

    if (ntohs(eth->etherType) != 0x0800) return;

    struct ipHeader *ip = (struct ipHeader *)(packet + sizeof(struct ethHeader));
    int ipHeaderLength = ip->iph_ihl * 4;

    if (header->len < sizeof(struct ethHeader) + ipHeaderLength) return;

    if (ip->iph_protocol != 6) return;

    struct tcpHeader *tcp = (struct tcpHeader *)(packet + sizeof(struct ethHeader) + ipHeaderLength);

    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->etherSrcMac));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->etherDstMac));

    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("Source Port: %d\n", ntohs(tcp->tcpSrcPort));
    printf("Destination Port: %d\n", ntohs(tcp->tcpDstPort));

    int tcpHeaderLength = tcp->tcpOffset * 4;
    int totalHeaderSize = sizeof(struct ethHeader) + ipHeaderLength + tcpHeaderLength;

    if (header->len < totalHeaderSize) return;

    int payloadLength = header->len - totalHeaderSize;

    if (payloadLength > 0) {
        const u_char *payload = packet + totalHeaderSize;
        int printLength = payloadLength < 16 ? payloadLength : 16;

        printf("Packet Payload (%d bytes): ", printLength);
        for (int i = 0; i < printLength; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    } else {
        printf("No packet payload.\n");
    }

    printf("\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packetCapture, NULL);

    pcap_close(handle);

    return 0;
}
