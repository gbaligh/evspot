#pragma once
#ifndef __EVSIP_NET_STACK_H__
#define __EVSIP_NET_STACK_H__


struct evspot_stack_s {
  /* Raw */
  uint8_t *raw;
  size_t raw_len;
  uint8_t *payload;
  size_t payload_len;

  /* Ethernet */
  const struct ether_header *eth;

  /* VLAN */

  /* ARP */

  /* PPP */

  /* IPv4/IPv6 */
  struct iphdr *ipv4;

  /* TCP/UDP */
};

uint8_t evspot_stack_eth(struct evspot_stack_s *pCtx);

uint8_t evspot_stack_vlan(struct evspot_stack_s *pCtx);

uint8_t evspot_stack_ipv4(struct evspot_stack_s *pCtx);

#endif /* __EVSIP_NET_STACK_H__ */
// vim: ts=2:sw=2:expandtab
