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

static struct evspot_stack_ip_upper_s {
  uint8_t proto;
  const char *desc;
  uint8_t (*stack_cb)(struct evspot_stack_s *pCtx);
} gIpUpper[] = {
  {IPPROTO_TCP,  "TCP",   &evspot_stack_tcp},
  {IPPROTO_UDP,  "UDP",   &evspot_stack_udp},
  {IPPROTO_ICMP, "ICMP",  &evspot_stack_icmp}
};

static uint8_t evspot_stack_ip_parser(struct evspot_stack_s *pCtx, uint8_t proto)
{
  unsigned int _i = 0;

  for (_i=0; _i < sizeof(gIpUpper)/sizeof(gIpUpper[0]); ++_i) {
    if (gIpUpper[_i].proto == proto) {
      if (gIpUpper[_i].stack_cb != NULL) {
        return gIpUpper[_i].stack_cb(pCtx);
      }
      else {
        _E("Header %s not supported", gIpUpper[_i].desc);
        return 0;
      }
    }
  }

  _E("IP protocol 0x%2X not supported", proto);
  return 0;
}

uint8_t evspot_stack_ipv4(struct evspot_stack_s *pCtx)
{
  const struct iphdr *h = NULL;
  uint8_t *raw = pCtx->payload;
  size_t raw_len = pCtx->payload_len;
  uint8_t *n_raw = NULL;
  size_t n_size = 0;
  struct in_addr source, dest;

  if (raw_len < sizeof(struct iphdr)) {
    _E("Wrong packet size");
    return 1;
  }

  h = (struct iphdr*)raw;
  n_raw = (raw + sizeof(struct iphdr));
  n_size = raw_len - sizeof(struct iphdr);

  if (h->version != IPVERSION) {
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

  return evspot_stack_ip_parser(pCtx, h->protocol);
}

// vim: ts=2:sw=2:expandtab
