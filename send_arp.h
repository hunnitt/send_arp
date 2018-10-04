typedef struct arp_packet {
    // Ethernet
    __uint8_t dst[6];    //mac destination.
    __uint8_t src[6];    //mac source.
    __uint16_t type;    //protocol type.

    // ARP
    __uint16_t hw_type;    //hardware type.
    __uint16_t p_type;    //protocol type.
    __uint8_t hw_len;    //hardware address length.
    __uint8_t p_len;    //protocol address length.
    __uint16_t op;    //operation.
    __uint8_t s_hw_addr[6];    //sender hardware address.
    __uint8_t s_p_addr[4];    //sender protocol address.
    __uint8_t t_hw_addr[6];    //target hardware address.
    __uint8_t t_p_addr[4];    //target protocol address.
} ARP_pkt;

#define ARP_size sizeof(ARP_pkt)

void str_ip(const char * ipstr, __uint8_t * ipbuf);

int get_mac(__uint8_t * buf);

int get_ip(__uint8_t * buf);

void ARP_req_init(ARP_pkt * arp_request,
                  __uint8_t * my_mac,
                  __uint8_t * my_ip,
                  __uint8_t * target_ip);

void ARP_pkt_dump(ARP_pkt * arppkt);

void ARP_atk_init(ARP_pkt * arp_attack,
                  __uint8_t * sender_mac,
                  __uint8_t * my_mac,
                  __uint8_t * target_ip,
                  __uint8_t * sender_ip);

void dump(const u_char * pkt);

