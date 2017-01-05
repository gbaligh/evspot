#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <evspot_utils.h>
#include <evspot_net.h>
#include "stack.h"

uint8_t evspot_stack_ipv4(struct evspot_stack_s *pCtx)
{
  const struct iphdr *h = NULL;
  uint8_t *raw = pCtx->payload;
  size_t raw_len = pCtx->payload_len;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;
  struct in_addr source, dest;

  if (raw_len < sizeof(struct ip)) {
    _E("Wrong packet size");
    return 1;
  }

  h = (struct iphdr*)raw;
  n_raw = (raw + sizeof(struct iphdr));
  n_size = raw_len - sizeof(struct iphdr);

  if (h->version != 0x4) {
    _E("Only IPv4 is supported");
    return 1;
  }

  pCtx->ipv4 = h;
  pCtx->payload = n_raw;
  pCtx->payload_len = n_size;

  memset(&source, 0, sizeof(source));
  source.s_addr = h->saddr;

  memset(&dest, 0, sizeof(dest));
  dest.s_addr = h->daddr;

  _I("Header IP");
  _I("   |-%-21s : %d", "IP Version", (unsigned int)h->version);
  _I("   |-%-21s : %d", "TTL", (unsigned int)h->ttl);
  _I("   |-%-21s : %d", "Protocol", (unsigned int)h->protocol);
  _I("   |-%-21s : %d", "Checksum", ntohs(h->check));
  _I("   |-%-21s : %s", "Source IP", inet_ntoa(source));
  _I("   |-%-21s : %s", "Destination IP", inet_ntoa(dest));

  return 0;
}

// vim: ts=2:sw=2:expandtab
