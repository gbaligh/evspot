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
#include "../link.h"

#define EVSPOT_PCAP_MAGIC 0x23002017

uint8_t evspot_pcap_init(evspot_link_t **ppCtx, const char *name)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)0;
  char errbuf[PCAP_ERRBUF_SIZE];

  _pCtx = (struct evspot_pcap_s *)tcmalloc(sizeof(struct evspot_pcap_s));
  if (_pCtx == (struct evspot_pcap_s *)0) {
    TCDPRINTF("Error memory allocation");
    return 1;
  }
  memset(_pCtx, 0, sizeof(struct evspot_pcap_s));

  _pCtx->magic = EVSPOT_PCAP_MAGIC;
  _pCtx->direction = PCAP_D_INOUT;
  _pCtx->name = name;
  _pCtx->promisc = 1;
  _pCtx->snaplen = 2048;
  _pCtx->timeout = 500;
  _pCtx->verbose = 1;

#ifdef DEBUG
  _pCtx->pcap = pcap_open_offline("/tmp/evspot.pcap", errbuf);
#else
  _pCtx->pcap = pcap_create(_pCtx->name, errbuf);
#endif
  if (_pCtx->pcap == NULL) {
    tcfree(_pCtx);
    return 1;
  }

  *ppCtx = (evspot_link_t *)_pCtx;

  return 0;
}

uint8_t evspot_pcap_start(evspot_link_t *pCtx)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  char errbuf[PCAP_ERRBUF_SIZE];

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAP_MAGIC, return 1);

 if (pcap_can_set_rfmon(_pCtx->pcap)) {
    if (pcap_set_rfmon(_pCtx->pcap, 1) < 0) {
      TCDPRINTF("Error rfmon");
    }
  }
  
  if (pcap_set_promisc(_pCtx->pcap, _pCtx->promisc) < 0) {
    TCDPRINTF("Error promisc");
  }
  
  if (pcap_set_snaplen(_pCtx->pcap, _pCtx->snaplen) < 0) {
    TCDPRINTF("Error snaplen");
  } 
  
  if (pcap_set_timeout(_pCtx->pcap, _pCtx->timeout) < 0) {
    TCDPRINTF("Error timeout");
  }

#ifndef DEBUG
  if (pcap_setdirection(_pCtx->pcap, _pCtx->direction) < 0) {
    TCDPRINTF("Error setting direction for device %s: %s", _pCtx->name, pcap_geterr(_pCtx->pcap));
  }

  if (pcap_activate(_pCtx->pcap) != 0) {
    TCDPRINTF("Error activate libpcap [%s] for device %s", pcap_geterr(_pCtx->pcap), _pCtx->name);
    return 1;
  }
#endif

  if (!pcap_getnonblock(_pCtx->pcap, errbuf)) {
    if (pcap_setnonblock(_pCtx->pcap, 1, errbuf) < 0) {
      TCDPRINTF("Error setting nonblock for device %s: %s", _pCtx->name, errbuf);
    }
  }

  TCDPRINTF("Using %s with device %s: DATALINK(%s:%s)",
      pcap_lib_version(),
      _pCtx->name, 
      pcap_datalink_val_to_name(pcap_datalink(_pCtx->pcap)),
      pcap_datalink_val_to_description(pcap_datalink(_pCtx->pcap)));

  return 0;
}

uint8_t evspot_pcap_getfd(evspot_link_t *pCtx, int *pfd)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  int _fd = -1;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAP_MAGIC, return 1);

  _fd = pcap_get_selectable_fd(_pCtx->pcap);

  if (_fd < 0) {
    TCDPRINTF("Error getting file descriptor !");
    return 1;
  }

  *pfd = _fd;

  return 0;
}

uint8_t evspot_pcap_read(evspot_link_t *pCtx, void *user, void (*cb)(void*,const size_t,const uint8_t*))
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  struct pcap_pkthdr *pkt_header = NULL;
  const u_char *pkt_data = NULL;
  int _ret = -2;


  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAP_MAGIC, return 1);

  _ret = pcap_next_ex(_pCtx->pcap, &pkt_header, &pkt_data);
  switch (_ret) {
    /* if the packet was read without problems */
    case 1:
      break;
    /* if packets are being read from a live capture and the timeout expired */
    case 0:
      break;
    /* if an error occurred while reading the packet */
    case -1:
      return 1;
    /* if  packets  are  being read  from  a  ``savefile''  and  there  are  no  more  packets to read from the savefile */
    case -2:
      return 1;
    /* Ignore */
    default:
      return 1;
  }

  if (cb != NULL) {
    cb(user, pkt_header->caplen, pkt_data);
  }

  return 0;
}

uint8_t evspot_pcap_stop(evspot_link_t *pCtx)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAP_MAGIC, return 1);
 
  return 0;
}

uint8_t evspot_pcap_free(evspot_link_t *pCtx)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  struct pcap_stat stats;
  
  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAP_MAGIC, return 1);
  
  if (pcap_stats(_pCtx->pcap, &stats) >= 0)
  {
    TCDPRINTF("Interface %s", _pCtx->name);
    TCDPRINTF("\t%d packets received", stats.ps_recv);
    TCDPRINTF("\t%d packets dropped", stats.ps_drop);
    TCDPRINTF("\t%d packet dropped by kernel", stats.ps_ifdrop);
  }

  pcap_close(_pCtx->pcap);

  tcfree(_pCtx);

  return 0;
}

const evspot_link_ops_t pcap_ops = {
  .init = evspot_pcap_init,
  .start = evspot_pcap_start,
  .getfd = evspot_pcap_getfd,
  .read = evspot_pcap_read,
  .stop = evspot_pcap_stop,
  .free = evspot_pcap_free,
}; 

// vim: ts=2:sw=2:expandtab
