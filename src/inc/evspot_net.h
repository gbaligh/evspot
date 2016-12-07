#ifndef __EVSIP_NET_H__
#define __EVSIP_NET_H__

#include <libnet.h>

struct event_base;

typedef struct evspot_net_ctx_s evspot_net_t;

uint8_t evspot_net_init(struct event_base *pBase, evspot_net_t **pCtx);

uint8_t evspot_net_start(evspot_net_t *pCtx);

uint8_t evspot_net_stop(evspot_net_t *pCtx);

uint8_t evspot_net_destroy(evspot_net_t *pCtx);

uint8_t evspot_net_eth_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len);

uint8_t evspot_net_ipv4_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len);

uint8_t evspot_net_tcp_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len);

uint8_t evspot_net_udp_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len);

uint8_t evspot_net_icmpv4_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len);

#endif /* __EVSIP_NET_H__ */

// vim: ts=2:sw=2:expandtab
