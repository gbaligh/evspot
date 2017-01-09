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
#include "stack.h"

static TCMDB *evspot_arp_mapping = NULL;

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

  pCtx->payload = n_raw;
  pCtx->payload_len = n_size;

  _I("Header ARP");
  _I("   |-%-21s : %d", "Operation", ntohs(h->ar_op));

  return 0;
}

// vim: ts=2:sw=2:expandtab
