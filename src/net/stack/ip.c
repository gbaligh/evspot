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
#include "stack.h"

uint8_t evspot_stack_ipv4(struct evspot_stack_s *pCtx)
{
  const struct iphdr *h = NULL;
  uint8_t *raw = pCtx->payload;
  size_t raw_len = pCtx->payload_len;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;

  if (raw_len < sizeof(struct iphdr)) {
    TCDPRINTF("Wrong packet size");
    return 1;
  }

  h = (struct iphdr*)raw;
  n_raw = (raw + sizeof(struct iphdr));
  n_size = raw_len - sizeof(struct iphdr);

  if (h->version != 0x4) {
    TCDPRINTF("Only IPv4 is supported");
    return 1;
  }

  pCtx->ipv4 = h;
  pCtx->payload = n_raw;
  pCtx->payload_len = n_size;

  TCDPRINTF("Header IPv4");

  return 0;
}

// vim: ts=2:sw=2:expandtab
