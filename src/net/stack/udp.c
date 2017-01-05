#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/udp.h>

#include <evspot_utils.h>
#include <evspot_net.h>
#include "stack.h"

uint8_t evspot_stack_udp(struct evspot_stack_s *pCtx)
{
  const struct udphdr *h = NULL;
  uint8_t *raw = pCtx->payload;
  size_t raw_len = pCtx->payload_len;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;
  struct in_addr source, dest;

  if (raw_len < sizeof(struct udphdr)) {
    _E("Wrong packet size");
    return 1;
  }

  h = (struct udphdr*)raw;
  n_raw = (raw + sizeof(struct udphdr));
  n_size = raw_len - sizeof(struct udphdr);

  _I("Header UDP");
  _I("   |-%-21s : %d", "Source Port", ntohs(h->source));
  _I("   |-%-21s : %d", "Destination Port", ntohs(h->dest));

  return 0;
}

// vim: ts=2:sw=2:expandtab
