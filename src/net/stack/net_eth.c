#define _BSD_SOURCE 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <evspot_utils.h>
#include <evspot_net.h>

uint8_t evspot_net_eth_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len)
{
	struct libnet_ethernet_hdr *h = NULL;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;
  uint8_t with_payload = 1;

  if (raw_len < sizeof(struct libnet_ethernet_hdr)) {
    return 1;
  }

	h = (struct libnet_ethernet_hdr*)raw;
	n_raw = (raw + sizeof(struct libnet_ethernet_hdr));
  n_size = raw_len - sizeof(struct libnet_ethernet_hdr);
	
  switch (ntohs(h->ether_type)) {
    /* IP protocol */
    case ETHERTYPE_IP:
      with_payload = evspot_net_ipv4_parse(libnet_ctx, n_raw, n_size);
      break;

    /* addr. resolution protocol */
    case ETHERTYPE_ARP:
      fprintf(stderr, "ARP\n");
      break;

    /* reverse addr. resolution protocol */
    case ETHERTYPE_REVARP:
      break;

    /* IEEE 802.1Q VLAN tagging */
    case ETHERTYPE_VLAN:
      break;

    /* IEEE 802.1X EAP authentication */
    case ETHERTYPE_EAP:
      break;

    /* used to test interfaces */
    case ETHERTYPE_LOOPBACK:
      break;

    default:
      fprintf(stderr, "Unknown ethernet type %04x\n", ntohs(h->ether_type));
      break;
  }
   
  /* Build Ethernet header */
  libnet_build_link(
      h->ether_dhost, 
      h->ether_shost, 
      NULL, 
      ntohs(h->ether_type), 
      with_payload?n_raw:0, with_payload?n_size:0, libnet_ctx, 0);
	
	return 0;
}

// vim: ts=2:sw=2:expandtab
