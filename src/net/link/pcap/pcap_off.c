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
#include <evspot_cfg.h>
#include <evspot_net.h>
#include <evspot_core.h>
#include "../link.h"

#define EVSPOT_PCAPOFF_MAGIC 0x18362017

uint8_t evspot_pcapoff_init(evspot_link_t **ppCtx, const char *name)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)0;
 
  _pCtx = (struct evspot_pcap_s *)tcmalloc(sizeof(struct evspot_pcap_s));
  if (_pCtx == (struct evspot_pcap_s *)0) {
    _E("Error memory allocation");
    return 1;
  }
  memset(_pCtx, 0, sizeof(struct evspot_pcap_s));

  _pCtx->magic = EVSPOT_PCAPOFF_MAGIC;
  _pCtx->direction = PCAP_D_IN;
  _pCtx->name = name;
  _pCtx->promisc = 1;
  _pCtx->snaplen = 2048;
  _pCtx->timeout = 500;
  _pCtx->verbose = 1;

  *ppCtx = (evspot_link_t *)_pCtx;

  return 0;
}

uint8_t evspot_pcapoff_start(evspot_link_t *pCtx)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  char errbuf[PCAP_ERRBUF_SIZE];

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAPOFF_MAGIC, return 1);

  _I("Using the offline file %s", _pCtx->name);
  _pCtx->pcap = pcap_open_offline(_pCtx->name, errbuf);
  if (_pCtx->pcap == NULL) {
    _E("Error creating pcap handler: %s", errbuf);
    return 1;
  }

  _I("Using %s with file %s: DATALINK(%s:%s)",
      pcap_lib_version(),
      _pCtx->name, 
      pcap_datalink_val_to_name(pcap_datalink(_pCtx->pcap)),
      pcap_datalink_val_to_description(pcap_datalink(_pCtx->pcap)));

  return 0;
}

uint8_t evspot_pcapoff_getfd(evspot_link_t *pCtx, int *pfd)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  int _fd = -1;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAPOFF_MAGIC, return 1);

  _fd = pcap_get_selectable_fd(_pCtx->pcap);

  if (_fd < 0) {
    _E("Error getting file descriptor !");
    return 1;
  }

  *pfd = _fd;

  return 0;
}

uint8_t evspot_pcapoff_read(evspot_link_t *pCtx, void *user, void (*cb)(void*,const size_t,const uint8_t*))
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  struct pcap_pkthdr *pkt_header = NULL;
  const u_char *pkt_data = NULL;
  int _ret = -2;


  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAPOFF_MAGIC, return 1);

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
      _E("Error pcap_next(): %s", pcap_geterr(_pCtx->pcap));
      return 1;
    /* if  packets  are  being read  from  a  ``savefile''  and  there  are  no  more  packets to read from the savefile */
    case -2:
      break;
    /* Ignore */
    default:
      return 1;
  }
  
  if (cb != NULL) {
    cb(user, pkt_header->caplen, pkt_data);
  }

  return 0;
}

uint8_t evspot_pcapoff_stop(evspot_link_t *pCtx)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAPOFF_MAGIC, return 1);
 
  pcap_close(_pCtx->pcap);

  return 0;
}

uint8_t evspot_pcapoff_free(evspot_link_t *pCtx)
{
  struct evspot_pcap_s *_pCtx = (struct evspot_pcap_s *)pCtx;
  
  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_PCAPOFF_MAGIC, return 1);
 
  tcfree(_pCtx);

  return 0;
}

const evspot_link_ops_t pcapoff_ops = {
  .init = evspot_pcapoff_init,
  .start = evspot_pcapoff_start,
  .getfd = evspot_pcapoff_getfd,
  .read = evspot_pcapoff_read,
  .stop = evspot_pcapoff_stop,
  .free = evspot_pcapoff_free,
}; 

// vim: ts=2:sw=2:expandtab
