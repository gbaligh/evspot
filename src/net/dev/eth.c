#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <event2/event.h>
#include <event2/util.h>

#include <evspot_utils.h>
#include <evspot_net.h>

#define EVSPOT_DEV_MAGIC 0x21432017

struct evspot_dev_s {
  uint32_t magic;
  struct event_base *base;
  struct event *ev;

  evspot_stack_t *stack;

  const char *name;
  uint8_t idx;
  uint8_t direction;
  struct in_addr ipv4;
  struct in_addr mask;
  struct in_addr brcst;
  uint32_t mtu;
  uint32_t kflags;
  
  struct {
    pcap_t *ctx;
    uint8_t promisc;
    uint32_t snaplen;
    uint8_t verbose;
    uint32_t timeout;
  } libpcap;
};

static void evspot_dev_event_handler(evutil_socket_t fd, short event, void *arg);

static void evspot_dev_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

uint8_t evspot_dev_init(evspot_dev_t **ppCtx, const char *name, struct event_base *base)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)0;

  _pCtx = (struct evspot_dev_s *)tcmalloc(sizeof(struct evspot_dev_s));
  if (_pCtx == (struct evspot_dev_s *)0) {
    return 1;
  }

  memset(_pCtx, 0, sizeof(struct evspot_dev_s));

  evspot_stack_init(&_pCtx->stack);

  _pCtx->name = name;
  _pCtx->base = base;
  
  /* Default values */
  _pCtx->magic = EVSPOT_DEV_MAGIC;
  _pCtx->direction = PCAP_D_IN;
  _pCtx->libpcap.promisc = 1;
  _pCtx->libpcap.snaplen = 1500;
  _pCtx->libpcap.timeout = 500;
  _pCtx->libpcap.verbose = 1;

  /* Ok */
  *ppCtx = _pCtx;

  return 0;
}

uint8_t evspot_dev_open(evspot_dev_t *pCtx)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;
  char errbuf[PCAP_ERRBUF_SIZE];

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  _pCtx->libpcap.ctx = 
#ifdef DEBUG
    pcap_open_offline("/tmp/evspot.pcap", errbuf);
#else
    pcap_create(_pCtx->name, errbuf);
#endif
  if (_pCtx->libpcap.ctx == NULL) {
    TCDPRINTF("Error creating libpcap ctx for %s: %s\n", _pCtx->name, errbuf);
    return 1;
  }

  if (pcap_setnonblock(_pCtx->libpcap.ctx, 1, errbuf) < 0) {
    TCDPRINTF("Error setting nonblock for device %s: %s\n", _pCtx->name, errbuf);
  }
  
  if (pcap_lookupnet(_pCtx->name, (bpf_u_int32 *)&_pCtx->ipv4, (bpf_u_int32 *)&_pCtx->mask, errbuf) != 0) {
    TCDPRINTF("Error getting interface %s information: %s\n", _pCtx->name, errbuf);
    return 1;
  }

  if (pcap_setdirection(_pCtx->libpcap.ctx, _pCtx->direction) < 0) {
    TCDPRINTF("Error setting direction for device %s: %s\n", _pCtx->name, pcap_geterr(_pCtx->libpcap.ctx));
  }

#ifndef DEBUG
  if (pcap_activate(_pCtx->libpcap.ctx) != 0) {
    TCDPRINTF("Error activate libpcap [%s] for device %s\n", pcap_geterr(_pCtx->libpcap.ctx), _pCtx->name);
    return 1;
  }
#endif

  _pCtx->ev = event_new(_pCtx->base, 
      pcap_get_selectable_fd(_pCtx->libpcap.ctx), 
      EV_READ|EV_PERSIST, 
      evspot_dev_event_handler, 
      _pCtx);

  TCDPRINTF("Using %s with device %s: DATALINK(%s:%s)\n",
      pcap_lib_version(),
      _pCtx->name, 
      pcap_datalink_val_to_name(pcap_datalink(_pCtx->libpcap.ctx)),
      pcap_datalink_val_to_description(pcap_datalink(_pCtx->libpcap.ctx)));

  if (event_add(_pCtx->ev, 0) != 0) {
    TCDPRINTF("Error adding libpcap event\n");
    return 1;
  }

  return 0;
}

uint8_t evspot_dev_setpromisc(evspot_dev_t *pCtx, uint8_t promisc)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  _pCtx->libpcap.promisc = promisc;
  if (pcap_set_promisc(_pCtx->libpcap.ctx, promisc) != 0) {
    TCDPRINTF("Error setting promisc mode for device %s\n", _pCtx->name);
    return 1;
  }

  return 0;
}

uint8_t evspot_dev_setsnaplen(evspot_dev_t *pCtx, uint32_t snaplen)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  _pCtx->libpcap.snaplen = snaplen;
  if (pcap_set_snaplen(_pCtx->libpcap.ctx, snaplen) != 0) {
    TCDPRINTF("Error setting snaplen for device %s\n", _pCtx->name);
    return 1;
  }

  return 0;
}

uint8_t evspot_dev_settimeout(evspot_dev_t *pCtx, uint32_t timeout)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  _pCtx->libpcap.timeout = timeout;
  if (pcap_set_timeout(_pCtx->libpcap.ctx, timeout) != 0) {
    TCDPRINTF("Error setting timeout for device %s\n", _pCtx->name);
    return 1;
  }

  return 0;
}

uint8_t evspot_dev_close(evspot_dev_t *pCtx)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  pcap_close(_pCtx->libpcap.ctx);

  return 0;
}

uint8_t evspot_dev_free(evspot_dev_t *pCtx)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  evspot_stack_free(_pCtx->stack);

  tcfree(_pCtx);

  return 0;
}

static void evspot_dev_event_handler(evutil_socket_t fd, short event, void *arg)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)arg;
  evutil_socket_t _fd = -1;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return);

  _fd = pcap_get_selectable_fd(_pCtx->libpcap.ctx);

  if (_fd != fd) {
    TCDPRINTF("Error: not the same socket for Ctx(%p)", _pCtx);
    return;
  }

  if (event & EV_READ) {
    int _i = 0;
    TCDPRINTF("New READ event detected on device %s", _pCtx->name);
    _i = pcap_dispatch(_pCtx->libpcap.ctx, 1, evspot_dev_pcap_handler, (u_char *)_pCtx);
    if (_i == 0) {
      TCDPRINTF("Error: could not read packet!");
#ifdef DEBUG
      exit(2);
#endif
    }
  }
}

static void evspot_dev_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)user;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return);

  //TCDPRINTF(">==== packet on %s with size %d", _pCtx->name, h->caplen);

  evspot_stack_parse(_pCtx->stack, bytes, h->caplen);
}

// vim: ts=2:sw=2:expandtab
