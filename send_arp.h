#pragma pack(push, 1)

struct ethernet_header {
    // Ethernet
    uint8_t dst[6];    //mac destination.
    uint8_t src[6];    //mac source.
    uint16_t type;     //protocol type.
};

struct arp_header {
    // ARP
    uint16_t hw_type;       //hardware type.
    uint16_t p_type;        //protocol type.
    uint8_t hw_len;         //hardware address length.
    uint8_t p_len;          //protocol address length.
    uint16_t op;            //operation.
    uint8_t s_hw_addr[6];   //sender hardware address.
    uint8_t s_p_addr[4];    //sender protocol address.
    uint8_t t_hw_addr[6];   //target hardware address.
    uint8_t t_p_addr[4];    //target protocol address.
};

typedef struct arp_packet {
    struct ethernet_header eh;
    struct arp_header ah;
} ARP_pkt; 

#define ETH_size            sizeof(struct ethernet_header)
#define ARP_size            sizeof(ARP_pkt) // 42 Bytes
#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_IP        0x0800
#define ARP_HWTYPE_MAC      0x0001
#define ARP_PTYPE_IPv4      0x0800
#define ARP_HW_LEN          0x06
#define ARP_P_LEN           0x04
#define ARP_OP_REQ          0x0001
#define ARP_OP_REP          0x0002

#pragma pack(pop)

const uint8_t BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t UNKNOWN[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void str_to_ip(uint8_t * ip, 
               char * ipstr);

int get_mac(uint8_t * my_mac, 
            const char * interface);

int get_ip(uint8_t * my_ip, 
           const char * interface);

void dump(const u_char * pkt, 
          int size);

void ARP_init(ARP_pkt * arp_request,
              uint8_t * eth_dst,
              uint8_t * eth_src,
              const uint16_t eth_type,
              const uint16_t arp_op,
              uint8_t * s_hw_addr,
              uint8_t * s_p_addr,
              uint8_t * t_hw_addr,
              uint8_t * t_p_addr);

void send_ARP_req(uint8_t * my_mac,
                  uint8_t * my_ip,
                  uint8_t * target_ip, 
                  pcap_t * handle);

void recv_ARP_rep(uint8_t * target_mac, 
                  uint8_t * mac_buf, 
                  pcap_t * handle);

void send_fake_ARP_rep(uint8_t * sender_mac,                       
                       uint8_t * sender_ip,
                       uint8_t * my_mac,
                       uint8_t * my_ip,
                       pcap_t * handle);