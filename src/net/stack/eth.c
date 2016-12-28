#define _BSD_SOURCE 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <pcap/vlan.h>

#include <evspot_utils.h>
#include <evspot_net.h>
#include "stack.h"

struct evspot_stack_eth_upper_s {
  uint16_t ethtype;
  const char *desc;
  uint8_t (*stack_cb)(struct evspot_stack_s *pCtx);
} gUpper[] = {
  {ETHERTYPE_IP,      "IPv4",             &evspot_stack_ipv4},
  {ETHERTYPE_IPV6,    "IPv6",             NULL},
  {ETHERTYPE_IPX,     "IPX",              NULL},
  {ETHERTYPE_ARP,     "ARP",              NULL},
  {ETHERTYPE_REVARP,  "RevARP",           NULL},
  {ETHERTYPE_AT,      "AppleTalk",        NULL},
  {ETHERTYPE_AARP,    "AppleTalk ARP",    NULL},
  {ETHERTYPE_LOOPBACK,"Test",             NULL},
  {ETHERTYPE_TRAIL,   "Trail",            NULL},
  {ETHERTYPE_VLAN,    "VLAN",             &evspot_stack_vlan},
  {ETH_P_PPP_SES,     "PPP SESSION",      NULL},
  {ETH_P_PPP_DISC,    "PPP DISCOVER",     NULL}
};

static uint8_t evspot_stack_eth_parser(struct evspot_stack_s *pCtx, uint16_t ethtype)
{
  unsigned int _i = 0;

  for (_i=0; _i < sizeof(gUpper)/sizeof(gUpper[0]); ++_i) {
    if (gUpper[_i].ethtype == ethtype) {
      if (gUpper[_i].stack_cb != NULL) {
        return gUpper[_i].stack_cb(pCtx);
      }
      else {
        TCDPRINTF("Header %s not supported", gUpper[_i].desc);
        return 0;
      }
    }
  }

  TCDPRINTF("Ethernet type 0x%2X not supported", ethtype);
  return 0;
}

uint8_t evspot_stack_eth(struct evspot_stack_s *pCtx)
{
  const struct ether_header *h = NULL;
  uint8_t *raw = pCtx->payload;
  size_t raw_len = pCtx->payload_len;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;

  if (raw_len < sizeof(struct ether_header)) {
    TCDPRINTF("Wrong packet size");
    return 1;
  }

  h = (struct ether_header*)raw;
  n_raw = (raw + sizeof(struct ether_header));
  n_size = raw_len - sizeof(struct ether_header);

  pCtx->eth = h;
  pCtx->payload = n_raw;
  pCtx->payload_len = n_size;

  TCDPRINTF("Header Ethernet");

  return evspot_stack_eth_parser(pCtx, ntohs(h->ether_type));
}

uint8_t evspot_stack_vlan(struct evspot_stack_s *pCtx)
{
  const struct vlan_tag *h = NULL;
  uint8_t *raw = pCtx->payload;
  size_t raw_len = pCtx->payload_len;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;

  if (raw_len < sizeof(struct vlan_tag)) {
    TCDPRINTF("Wrong packet size");
    return 1;
  }

  h = (struct vlan_tag*)raw;
  n_raw = (raw + sizeof(struct vlan_tag));
  n_size = raw_len - sizeof(struct vlan_tag);

  //pCtx->eth = h;
  pCtx->payload = n_raw;
  pCtx->payload_len = n_size;

  TCDPRINTF("Header VLAN");

  return evspot_stack_eth_parser(pCtx, ntohs(h->vlan_tci));
}


// vim: ts=2:sw=2:expandtab
