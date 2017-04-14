#pragma once
#ifndef __EVSIP_NET_H__
#define __EVSIP_NET_H__

#include <libnet.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define EVSPOT_LINK_TYPE_PCAP   0
#define EVSPOT_LINK_TYPE_SRAW   1
#define EVSPOT_LINK_TYPE_NFQ    2
#define EVSPOT_LINK_TYPE_PCAPOFF 3

struct event_base;

struct evspot_app_s;

typedef struct evspot_net_ctx_s evspot_net_t;

typedef struct evspot_dev_s evspot_dev_t;

typedef struct evspot_stack_s evspot_stack_t;

/* Network stack API */

uint8_t evspot_net_init(struct evspot_app_s *pAppCtx, evspot_net_t **ppCtx);

uint8_t evspot_net_start(evspot_net_t *pCtx);

uint8_t evspot_net_dev_add(evspot_net_t *pCtx, const char *name, const uint32_t type);

uint8_t evspot_net_stop(evspot_net_t *pCtx);

uint8_t evspot_net_destroy(evspot_net_t *pCtx);

/* Device API */

uint8_t evspot_dev_init(evspot_dev_t **ppCtx, const char *name, const uint32_t type, struct event_base *base);

uint8_t evspot_dev_open(evspot_dev_t *pCtx);

const char *evspot_dev_getname(evspot_dev_t *pCtx);

uint8_t evspot_dev_setpromisc(evspot_dev_t *pCtx, uint8_t promisc);

uint8_t evspot_dev_setsnaplen(evspot_dev_t *pCtx, uint32_t snaplen);

uint8_t evspot_dev_settimeout(evspot_dev_t *pCtx, uint32_t timeout);

uint8_t evspot_dev_close(evspot_dev_t *pCtx);

uint8_t evspot_dev_free(evspot_dev_t *pCtx);

#endif /* __EVSIP_NET_H__ */

// vim: ts=2:sw=2:expandtab
