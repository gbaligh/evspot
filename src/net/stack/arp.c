#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <net/if_arp.h>

#include <evspot_utils.h>
#include <evspot_net.h>
#include <netinet/if_ether.h>
#include "stack.h"

static TCMDB *arp_table = NULL;

static void evspot_stack_arp_dump(void)
{
  uint8_t *m = NULL;
  uint8_t *p = NULL;
  int psp = 0;

  if (arp_table == NULL) {
    return;
  }

  tcmdbiterinit(arp_table);
  while ((p = tcmdbiternext(arp_table, &psp)) != NULL) {
    int msp;
    m = tcmdbget(arp_table, p, psp, &msp);
    _I("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", m[0], m[1], m[2], m[3], m[4], m[5]);
    tcfree(m);
    tcfree(p);
  }
}

static uint8_t evspot_stack_arp_insert(struct ether_arp *req)
{
  if (arp_table == NULL) {
    arp_table = tcmdbnew();
  }

  tcmdbputkeep(arp_table, req->arp_spa, sizeof(req->arp_spa), req->arp_sha, sizeof(req->arp_sha));

  return 0;
}

static uint8_t evspot_stack_arp_parse(struct evspot_stack_s *pCtx)
{
  uint16_t header = ntohs(pCtx->arp->ar_hrd);
  uint16_t oper = ntohs(pCtx->arp->ar_op);

  if (header != ARPHRD_ETHER) {
    _D("Not supported ARP header");
    return 1;
  }

  if (pCtx->arp->ar_hln != ETH_ALEN) {
    _D("Not supported MAC address size");
    return 1;
  }

  if (pCtx->arp->ar_pln != sizeof(uint32_t)) {
    _D("Not supported IPv4 address size");
    return 1;
  }

  switch (oper) {
    case ARPOP_REQUEST:
      {
        struct ether_arp *h = (struct ether_arp *)pCtx->arp;
        evspot_stack_arp_insert(h); 
      }
      break;
    case ARPOP_REPLY:
      _D("ARP reply");
      break;
    case ARPOP_RREQUEST:
      _D("RARP request");
      break;
    case ARPOP_RREPLY:
      _D("RARP reply");
      break;
    case ARPOP_InREQUEST:
      _D("InARP request");
      break;
    case ARPOP_InREPLY:
      _D("InARP reply");
      break;
    case ARPOP_NAK:
      _D("(ATM) ARP NAK");
      break;
    default:
      _D("Unknown");
      break;
  }

  return 0;
}

uint8_t evspot_stack_arp(struct evspot_stack_s *pCtx)
{
  const struct arphdr *h = NULL;
  uint8_t *raw = pCtx->payload;
  size_t raw_len = pCtx->payload_len;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;

  if (raw_len < sizeof(struct arphdr)) {
    _E("Wrong packet size");
    return 1;
  }

  h = (struct arphdr*)raw;
  n_raw = (raw + sizeof(struct arphdr));
  n_size = raw_len - sizeof(struct arphdr);

  pCtx->arp = h;
  pCtx->payload = n_raw;
  pCtx->payload_len = n_size;

  _I("Header ARP");
  _I("   |-%-21s : %d", "Operation", ntohs(h->ar_op));

  evspot_stack_arp_parse(pCtx);

  return 0;
}

// vim: ts=2:sw=2:expandtab
