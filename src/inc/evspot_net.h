#pragma once
#ifndef __EVSIP_NET_H__
#define __EVSIP_NET_H__

#include <libnet.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct event_base;

struct evspot_app_s;

typedef struct evspot_net_ctx_s evspot_net_t;

typedef struct evspot_dev_s evspot_dev_t;

typedef struct evspot_stack_s evspot_stack_t;

uint8_t evspot_net_init(struct evspot_app_s *pAppCtx, evspot_net_t **ppCtx);

uint8_t evspot_net_start(evspot_net_t *pCtx);

uint8_t evspot_net_devadd(evspot_net_t *pCtx, const char *name);

uint8_t evspot_net_stop(evspot_net_t *pCtx);

uint8_t evspot_net_destroy(evspot_net_t *pCtx);

uint8_t evspot_dev_init(evspot_dev_t **ppCtx, const char *name, struct event_base *base);

uint8_t evspot_dev_open(evspot_dev_t *pCtx);

uint8_t evspot_dev_setpromisc(evspot_dev_t *pCtx, uint8_t promisc);

uint8_t evspot_dev_setsnaplen(evspot_dev_t *pCtx, uint32_t snaplen);

uint8_t evspot_dev_settimeout(evspot_dev_t *pCtx, uint32_t timeout);

uint8_t evspot_dev_close(evspot_dev_t *pCtx);

uint8_t evspot_dev_free(evspot_dev_t *pCtx);

uint8_t evspot_net_dev_add(evspot_net_t *pCtx, const char *name);

#endif /* __EVSIP_NET_H__ */

// vim: ts=2:sw=2:expandtab
