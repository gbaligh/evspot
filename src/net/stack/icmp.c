#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>

#include <evspot_utils.h>
#include <evspot_net.h>
#include "stack.h"


uint8_t evspot_stack_icmp(struct evspot_stack_s *pCtx)
{
  const struct icmphdr *h = NULL;
  uint8_t *raw = pCtx->payload;
  size_t raw_len = pCtx->payload_len;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;
  struct in_addr source, dest;

  if (raw_len < sizeof(struct icmphdr)) {
    _E("Wrong packet size");
    return 1;
  }

  h = (struct icmphdr*)raw;
  n_raw = (raw + sizeof(struct icmphdr));
  n_size = raw_len - sizeof(struct icmphdr);

  pCtx->icmp = h;
  pCtx->payload = n_raw;
  pCtx->payload_len = n_size;

  _I("Header ICMP");
  _I("   |-%-21s : %d", "Type", h->type);
  _I("   |-%-21s : %d", "Code", h->code);

  return 0;
}

// vim: ts=2:sw=2:expandtab
