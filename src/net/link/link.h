#pragma once
#ifndef __EVSPOT_NET_LINK_H__
#define __EVSPOt_NET_LINK_H__

struct evspot_link_s {
  uint32_t magic;
  uint32_t type;
  const char *name;
};
typedef struct evspot_link_s evspot_link_t;

struct evspot_pcap_s {
  uint32_t magic;
  uint32_t type;
  const char *name;
  pcap_t *pcap;
  uint8_t direction;
  uint32_t snaplen;
  uint32_t timeout;
  uint8_t promisc;
  uint8_t verbose;
};
typedef struct evspot_pcap_s evspot_pcap_t;

struct evspot_link_ops_s {
  uint8_t (*init)(evspot_link_t **ppCtx, const char *name);
  uint8_t (*start)(evspot_link_t *pCtx);
  uint8_t (*getfd)(evspot_link_t *pCtx, int *pfd);
  uint8_t (*read)(evspot_link_t *pCtx, void*, void (*cb)(void*,const size_t, const uint8_t*));
  uint8_t (*stop)(evspot_link_t *pCtx);
  uint8_t (*free)(evspot_link_t *pCtx);
};

typedef struct evspot_link_ops_s evspot_link_ops_t;

uint8_t evspot_link_init(evspot_link_t **ppCtx, uint32_t linktype, const char *name);

uint8_t evspot_link_start(evspot_link_t *pCtx);

uint8_t evspot_link_getfd(evspot_link_t *pCtx, int *pfd);

uint8_t evspot_link_read(evspot_link_t *pCtx, void *user, void (*cb)(void*,const size_t, const uint8_t*));

uint8_t evspot_link_stop(evspot_link_t *pCtx);

uint8_t evspot_link_free(evspot_link_t *pCtx);

#endif /* __EVSPOT_NET_LINK_H__ */
// vim: ts=2:sw=2:expandtab
