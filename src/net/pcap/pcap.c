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

#define EVSPOT_PCAP_MAGIC 0x23002017

struct evspot_pcap_s {
  int magic;
  pcap_t *pcap;
  uint32_t snaplen;
  uint32_t timeout;
  uint8_t promisc;
  uint8_t verbose;
};

typedef struct evspot_pcap_s evspot_pcap_t;

uint8_t evspot_pcap_init(evspot_pcap_t **ppCtx)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)0;

  _pCtx = (struct evspot_pcap_s *)tcmalloc(sizeof(struct evspot_pcap_s));
  if (_pCtx == (struct evspot_pcap_s *)0) {
    TCDPRINTF("Error memory allocation");
    return 1;
  }
  memset(_pCtx, 0, sizeof(struct evspot_pcap_s));

  _pCtx->magic = EVSPOT_PCAP_MAGIC;
  _pCtx->promisc = 1;
  _pCtx->snaplen = 1500;
  _pCtx->timeout = 500;
  _pCtx->verbose = 1;

  *ppCtx = _pCtx;

  return 0;
}

uint8_t evspot_pcap_start(evspot_pcap_t *pCtx)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  char errbuf[PCAP_ERRBUF_SIZE];

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAP_MAGIC, return 1);

  _pCtx->pcap = pcap_open_offline("/tmp/evspot.pcap", errbuf);
  if (_pCtx->pcap == NULL) {
    return 1;
  }

  return 0;
}

uint8_t evspot_pcap_stop(evspot_pcap_t *pCtx)
{
  return 0;
}

uint8_t evspot_pcap_free(evspot_pcap_t *pCtx)
{
  return 0;
}

// vim: ts=2:sw=2:expandtab
