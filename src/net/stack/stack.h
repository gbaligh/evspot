#pragma once
#ifndef __EVSIP_NET_STACK_H__
#define __EVSIP_NET_STACK_H__


struct evspot_stack_s {
  /* magic */
  uint32_t magic;

  /* Raw */
  uint8_t *raw;
  size_t raw_len;
  uint8_t *payload;
  size_t payload_len;

  /* Ethernet */
  const struct ethhdr *eth;

  /* VLAN */

  /* ARP */

  /* PPP */

  /* IPv4/IPv6 */
  const struct iphdr *ipv4;

  /* TCP/UDP */
};

uint8_t evspot_stack_eth(struct evspot_stack_s *pCtx);

uint8_t evspot_stack_vlan(struct evspot_stack_s *pCtx);

uint8_t evspot_stack_ipv4(struct evspot_stack_s *pCtx);

uint8_t evspot_stack_init(evspot_stack_t **ppCtx);

uint8_t evspot_stack_parse(evspot_stack_t *pCtx, uint8_t *raw, size_t raw_len);

uint8_t evspot_stack_free(evspot_stack_t *pCtx);

#endif /* __EVSIP_NET_STACK_H__ */
// vim: ts=2:sw=2:expandtab
