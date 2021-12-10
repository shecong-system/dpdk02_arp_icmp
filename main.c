#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <arpa/inet.h>

#define NUM_MBUFS (4096-1)
#define CACHE_SIZE 0
#define PRIV_SIZE 0
#define BURST_SIZE	32

static int g_port_id = 0;
static struct rte_ether_addr g_local_mac;

const char *local_addr_str = "192.168.160.89";
static struct in_addr g_local_ipaddr;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};


static int init_port(int port_id, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_dev_info dev_info;
    const uint16_t nb_rx_queues = 1;
    const uint16_t nb_tx_queues = 1;
    const struct rte_eth_conf eth_port_conf = port_conf_default;
    
    uint16_t nb_sysport = rte_eth_dev_count_avail();
    if(nb_sysport == 0)
    {
        rte_exit(EXIT_FAILURE, "Error support eth dev");
    }

    if(rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues, &eth_port_conf) != 0) 
    {
        rte_exit(EXIT_FAILURE, "Error configure eth dev\n");
    }

    if(rte_eth_rx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool) != 0) 
    {
        rte_exit(EXIT_FAILURE, "Error RX queue setup\n");
    }

    rte_eth_dev_info_get(port_id, &dev_info);
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = eth_port_conf.rxmode.offloads;
	if (rte_eth_tx_queue_setup(port_id, 0 , 1024, rte_eth_dev_socket_id(port_id), &txq_conf) < 0) 
	{
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
		
	}
	
    if(rte_eth_dev_start(port_id) != 0) 
    {
        rte_exit(EXIT_FAILURE, "Error Start eth dev\n");
    }

    printf("Success start eth dev: %d\n", port_id);
    return 0;
}

static struct rte_mbuf *encode_arp_reply_pkt(uint8_t *src_mac, uint8_t *dst_mac, 
                                    uint32_t src_ip, uint32_t dst_ip, struct rte_mempool *mbuf_pool)
{
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf)
    {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc");
        return NULL;
    }

    uint16_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;

    uint8_t *pkt = rte_pktmbuf_mtod(mbuf, uint8_t*);
    
    struct rte_ether_hdr *ethhdr = (struct rte_ether_hdr *)pkt;
    rte_memcpy(ethhdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethhdr->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    ethhdr->ether_type = htons(RTE_ETHER_TYPE_ARP);

    struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ethhdr + 1);
    arphdr->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arphdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arphdr->arp_hlen = 6;
    arphdr->arp_plen = 4;
    arphdr->arp_opcode = htons(RTE_ARP_OP_REPLY);
    
    rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    arphdr->arp_data.arp_sip = src_ip;
    
    rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    arphdr->arp_data.arp_tip = dst_ip;

    struct in_addr addr;
    addr.s_addr = arphdr->arp_data.arp_sip;

    printf("Sending: arp src ip=%s, ", inet_ntoa(addr));

    addr.s_addr = arphdr->arp_data.arp_tip;
    printf(" arp dst ip=%s \n", inet_ntoa(addr));    

    printf("Sending: arp src mac=%x-%x-%x-%x-%x-%x, ", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf(" dst mac=%x-%x-%x-%x-%x-%x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    return mbuf;
}

static void arp_request_process(struct rte_arp_hdr *arphdr, struct rte_mempool *mbuf_pool)
{                                        
    //check dst ip is local ip
    if(arphdr->arp_data.arp_tip != g_local_ipaddr.s_addr)
    {        
        return ;
    }

    // encode reply pkt
    struct rte_mbuf * reply_mbuf = encode_arp_reply_pkt(g_local_mac.addr_bytes, arphdr->arp_data.arp_sha.addr_bytes, 
                                                    g_local_ipaddr.s_addr, arphdr->arp_data.arp_sip, mbuf_pool);

    // send reply pkt
    if(rte_eth_tx_burst(g_port_id, 0, &reply_mbuf, 1) <= 0)
    {
        printf("Error Sending to eth\n");
    }
    			
    rte_pktmbuf_free(reply_mbuf);
}

static uint16_t icmp_checksum_calc(uint16_t *addr, int count) 
{
    register long sum = 0;

    while (count > 1) {

        sum += *(unsigned short*)addr++;
        count -= 2;
    
    }

    if (count > 0) {
        sum += *(unsigned char *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}



static struct rte_mbuf * encode_icmp_reply_pkt(uint8_t *src_mac, uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip,
                            uint16_t ident, uint16_t seq_nb, 
                            uint8_t *icmp_payload, uint16_t payload_len, struct rte_mempool *mbuf_pool)
{
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf)
    {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc");
        return NULL;
    }

    //eth
    uint16_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + payload_len;
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;

    uint8_t *pkt = rte_pktmbuf_mtod(mbuf, uint8_t*);
    
    struct rte_ether_hdr *ethhdr = (struct rte_ether_hdr *)pkt;
    rte_memcpy(ethhdr->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethhdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    ethhdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //ip
    struct rte_ipv4_hdr *i4hdr = (struct rte_ipv4_hdr *)(ethhdr+1);
    i4hdr->dst_addr = dst_ip;
    i4hdr->fragment_offset = 0;
    i4hdr->hdr_checksum = 0;
    i4hdr->next_proto_id = IPPROTO_ICMP;
    i4hdr->packet_id = 0;
    i4hdr->src_addr = src_ip;
    i4hdr->time_to_live = 64;
    i4hdr->total_length = htons(payload_len + sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr));
    i4hdr->type_of_service = 0;
    i4hdr->version_ihl = 0x45;
    i4hdr->hdr_checksum = rte_ipv4_cksum(i4hdr);

    //icmp
    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(i4hdr + 1);
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_ident = ident;
    icmphdr->icmp_seq_nb = seq_nb;
    icmphdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;

    //icmp payload
    rte_memcpy((uint8_t*)(icmphdr+1), icmp_payload, payload_len);
    icmphdr->icmp_cksum = icmp_checksum_calc((uint16_t *)icmphdr, sizeof(struct rte_icmp_hdr) + payload_len);

    struct in_addr addr;
    addr.s_addr = src_ip;

    printf("Sending: payload_len=%d, icmp src ip=%s, ", payload_len, inet_ntoa(addr));

    addr.s_addr = dst_ip;
    printf(" icmp dst ip=%s \n", inet_ntoa(addr));    

    printf("Sending: icmp src mac=%x-%x-%x-%x-%x-%x, ", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf(" dst mac=%x-%x-%x-%x-%x-%x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);


    return mbuf;
}

static void icmp_request_process(uint8_t *src_mac, uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip,
                            uint16_t ident, uint16_t seq_nb,  
                            uint8_t *icmp_payload, uint16_t payload_len, struct rte_mempool *mbuf_pool)
{
    struct rte_mbuf *reply_mbuf = encode_icmp_reply_pkt(src_mac, dst_mac, src_ip, dst_ip, ident, seq_nb, 
                                icmp_payload, payload_len, mbuf_pool);

    // send reply pkt
    if(rte_eth_tx_burst(g_port_id, 0, &reply_mbuf, 1) <= 0)
    {
        printf("Error Sending to eth\n");
    }
    			
    rte_pktmbuf_free(reply_mbuf);    
}

int main(int argc, char * argv[])
{
    uint16_t num_recvd, i;
    struct rte_mbuf *mbufs[BURST_SIZE];

    if(rte_eal_init(argc, argv) != 0)
    {
        rte_exit(EXIT_FAILURE, "rte_eal_init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS, CACHE_SIZE, PRIV_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(mbuf_pool == NULL) 
    {
        rte_exit(EXIT_FAILURE, "Error create mbuf pool");
    }

    rte_eth_macaddr_get(g_port_id, &g_local_mac);
    
    
    inet_aton(local_addr_str, &g_local_ipaddr);
    init_port(g_port_id, mbuf_pool);

    while(1)
    {
        num_recvd = rte_eth_rx_burst(g_port_id, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) 
		{
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		
		for (i = 0; i < num_recvd; i++) 
		{
		    struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            if(ehdr->ether_type == ntohs(RTE_ETHER_TYPE_ARP))
            {
                struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
                if(ahdr->arp_opcode == ntohs(RTE_ARP_OP_REQUEST))
                {
                    //arp request
                    arp_request_process(ahdr, mbuf_pool);
                }
                else if(ahdr->arp_opcode == ntohs(RTE_ARP_OP_REPLY))
                {
                    //arp reply
                }
            }
            else if(ehdr->ether_type == ntohs(RTE_ETHER_TYPE_IPV4))
            {
                struct rte_ipv4_hdr *i4hdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                if(i4hdr->next_proto_id == 1 && i4hdr->dst_addr == g_local_ipaddr.s_addr) //ICMP
                {
                    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(i4hdr+1);
                    if(icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST)
                    {
                        uint16_t icmp_paylen = ntohs(i4hdr->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_icmp_hdr);
                        //icmp req
                        icmp_request_process(g_local_mac.addr_bytes, ehdr->s_addr.addr_bytes, g_local_ipaddr.s_addr, i4hdr->src_addr, 
                                        icmphdr->icmp_ident, icmphdr->icmp_seq_nb, (uint8_t *)(icmphdr + 1), 
                                        icmp_paylen, mbuf_pool);
                    }
                    else if(icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REPLY)
                    {
                        //icmp reply
                    }
                }
            }
            rte_pktmbuf_free(mbufs[i]);
		}
    }

    return 0;
}


