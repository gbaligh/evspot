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
#include "link.h"

extern evspot_link_ops_t pcap_ops;
extern evspot_link_ops_t pcapoff_ops;

static const evspot_link_ops_t *link_ops[] = {
  [EVSPOT_LINK_TYPE_PCAP] = &pcap_ops,
  [EVSPOT_LINK_TYPE_SRAW] = NULL,
  [EVSPOT_LINK_TYPE_NFQ] = NULL,
  [EVSPOT_LINK_TYPE_PCAPOFF] = &pcapoff_ops,
};

uint8_t evspot_link_init(evspot_link_t **ppCtx, uint32_t linktype, const char *name)
{
  uint8_t _ret = 0;
  struct evspot_link_s *_pCtx = (struct evspot_link_s *)0;

  if (linktype > sizeof(link_ops)/sizeof(link_ops[0])) {
    TCDPRINTF("Error LINK type");
    return 1;
  }

  if (link_ops[linktype]->init == NULL) {
    TCDPRINTF("Error init operation not handled");
    return 1;
  }

  if (link_ops[linktype]->init(&_pCtx, name) != 0) {
    return 1;
  }

  _pCtx->type = linktype;
  *ppCtx = _pCtx;

  return _ret;
}

uint8_t evspot_link_start(evspot_link_t *pCtx)
{
  struct evspot_link_s *_pCtx = (struct evspot_link_s *)pCtx;
  
  if (_pCtx->type > sizeof(link_ops)/sizeof(link_ops[0])) {
    TCDPRINTF("Error LINK type");
    return 1;
  }

  if (link_ops[_pCtx->type]->start == NULL) {
    TCDPRINTF("Error start operation not handled");
    return 1;
  }

  return link_ops[_pCtx->type]->start(_pCtx);
}

uint8_t evspot_link_getfd(evspot_link_t *pCtx, int *pfd)
{
  struct evspot_link_s *_pCtx = (struct evspot_link_s *)pCtx;
  
  if (_pCtx->type > sizeof(link_ops)/sizeof(link_ops[0])) {
    TCDPRINTF("Error LINK type");
    return 1;
  }

  if (link_ops[_pCtx->type]->getfd == NULL) {
    TCDPRINTF("Error getfd operation not handled");
    return 1;
  }
  
  return link_ops[_pCtx->type]->getfd(_pCtx, pfd);
}

uint8_t evspot_link_read(evspot_link_t *pCtx, void *user, void (*cb)(void*,const size_t, const uint8_t*))
{
  struct evspot_link_s *_pCtx = (struct evspot_link_s *)pCtx;

  if (_pCtx->type > sizeof(link_ops)/sizeof(link_ops[0])) {
    TCDPRINTF("Error LINK type");
    return 1;
  }

  if (link_ops[_pCtx->type]->read == NULL) {
    TCDPRINTF("Error read operation not handled");
    return 1;
  }
 
  return link_ops[_pCtx->type]->read(_pCtx, user, cb);
}

uint8_t evspot_link_stop(evspot_link_t *pCtx)
{
  struct evspot_link_s *_pCtx = (struct evspot_link_s *)pCtx;

  if (_pCtx->type > sizeof(link_ops)/sizeof(link_ops[0])) {
    TCDPRINTF("Error LINK type");
    return 1;
  }

  if (link_ops[_pCtx->type]->stop == NULL) {
    TCDPRINTF("Error stop operation not handled");
    return 1;
  }
 
  return link_ops[_pCtx->type]->stop(_pCtx);
}

uint8_t evspot_link_free(evspot_link_t *pCtx)
{
  struct evspot_link_s *_pCtx = (struct evspot_link_s *)pCtx;

  if (_pCtx->type > sizeof(link_ops)/sizeof(link_ops[0])) {
    TCDPRINTF("Error LINK type");
    return 1;
  }

  if (link_ops[_pCtx->type]->free == NULL) {
    TCDPRINTF("Error free operation not handled");
    return 1;
  }
 
  return link_ops[_pCtx->type]->free(_pCtx);
}

// vim: ts=2:sw=2:expandtab
