#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethHeader {
    u_char  etherSrcMac[6];    // DST MAC Address 선언
    u_char  etherDstMac[6];    // SRC MAC Address 선언
    u_short etherType;        // Ethernet 타입 선언 (IP, ARP, RARP,...etc)
};

/* IP Header */
struct ipHeader {
    unsigned char      iph_ihl:4,   // IP Header length
                       iph_ver:4;   // IP Version
    unsigned char      iph_tos;     // Type of service
    unsigned short int iph_len;     // IP Packet length (data + header)
    unsigned short int iph_ident;   // Identification
    unsigned short int iph_flag:3,  // Fragmentation flags
                       iph_offset:13; // Flags offset
    unsigned char      iph_ttl;     // Time to Live
    unsigned char      iph_protocol; // Protocol type
    unsigned short int iph_chksum;  // IP datagram checksum
    struct in_addr     iph_sourceip; // Source IP address
    struct in_addr     iph_destip;   // Destination IP address
};

/* TCP Header */
struct tcpHeader {
    u_short tcpSrcPort;    // source port
    u_short tcpDstPort;    // destination port
    u_int   tcpSeq;      // sequence number
    u_int   tcpAck;      // acknowledgement number
    u_char  tcpOffset;    // data offset, reserved
    u_char  tcpFlags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcpWindow;      // tcp window
    u_short tcpChecksum;      // checksum
    u_short tcpurgent;      // urgent pointer
};

void packetCapture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    struct ethHeader *eth = (struct ethHeader *)packet;
    struct ipHeader *ip = (struct ipHeader *)(packet + sizeof(struct ethHeader));
    int ipHeaderLength = ip->iph_ihl * 4; // IP 헤더 길이는 4바이트 단위
    struct tcpHeader *tcp = (struct tcpHeader *)(packet + sizeof(struct ethHeader) + ipHeaderLength);

    // Ethernet Header: Src MAC / Dst MAC 출력
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->etherDstMac));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->etherSrcMac));

    // Src IP, Dst IP 출력
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    // TCP 포트 정보 출력
    printf("Source Port: %d\n", ntohs(tcp->tcpSrcPort));
    printf("Destination Port: %d\n", ntohs(tcp->tcpDstPort));

    // TCP 헤더 길이 계산 (상위 4비트: 헤더 길이, 단위 32비트)
    int tcp_header_length = ((tcp->tcpOffset & 0xF0) >> 4) * 4;
    int total_headers_size = sizeof(struct ethHeader) + ipHeaderLength + tcp_header_length;
    int payload_length = header->len - total_headers_size;

    // 페이로드(메시지) 출력 - 16진수로 출력
    if (payload_length > 0) {
        const u_char *payload = packet + total_headers_size;
        int print_length = payload_length < 16 ? payload_length : 16;
        printf("Packet Message (%d bytes): ", print_length);
        for (int i = 0; i < print_length; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    } else {
        printf("No packet message payload.\n");
    }
    
    printf("\n");
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // eth0 인터페이스에서 패킷 캡처
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // 무한 루프로 패킷 캡처
    pcap_loop(handle, 0, packetCapture, NULL);

    pcap_close(handle);

    return 0;
}

