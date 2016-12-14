#define _BSD_SOURCE 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <event2/event.h>
#include <event2/util.h>

#include <evspot_utils.h>
#include <evspot_net.h>

#define EVSPOT_NET_CTX_MAGIC 0x19820117

struct evspot_net_ctx_s {
  uint32_t          magic;
  struct event_base *base;
  TCPTRLIST *devs;
};

uint8_t evspot_net_init(struct event_base *pBase, evspot_net_t **pCtx)
{
  struct evspot_net_ctx_s *_pCtx = NULL;

  if (pBase == NULL) {
    fprintf(stderr, "Event base is NULL\n");
    return 1;
  }

  _pCtx = (struct evspot_net_ctx_s *)tcmalloc(sizeof(struct evspot_net_ctx_s));
  if (_pCtx == NULL) {
    fprintf(stderr, "allocation failed\n");
    return 1;
  }

  memset(_pCtx, 0, sizeof(struct evspot_net_ctx_s));
  
  _pCtx->devs = tcptrlistnew(); 
  if (_pCtx->devs == NULL) {
    fprintf(stderr, "Error creating devices list\n");
    free(_pCtx);
    return 1;
  }

  _pCtx->magic = EVSPOT_NET_CTX_MAGIC;
  _pCtx->base = pBase;
  *pCtx = _pCtx;

  return 0;
}

uint8_t evspot_net_devadd(evspot_net_t *pCtx, const char *name)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)pCtx;
  evspot_dev_t *_pDevCtx = NULL;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return 1);

  if (evspot_dev_init(&_pDevCtx, name, _pCtx->base) != 0) {
    fprintf(stderr, "Error initializing device %s\n", name);
    return 1;
  }

  fprintf(stderr, "New device created (%s:%p)\n", name, _pDevCtx);

  tcptrlistpush(_pCtx->devs, _pDevCtx);

  return 0;
}

uint8_t evspot_net_start(evspot_net_t *pCtx)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)pCtx;
  int _i = 0;
  int numDev = 0;
  int _aDev = 0;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return 1);

  if ((numDev = tcptrlistnum(_pCtx->devs)) == 0) {
    fprintf(stderr, "Error: no device created for network\n");
    return 1;
  }

  for (_i = 0; _i < numDev; ++_i) {
    evspot_dev_t *_pDevCtx = tcptrlistval(_pCtx->devs, _i);

    if (evspot_dev_open(_pDevCtx) != 0) {
      fprintf(stderr, "Error starting device %p\n", _pDevCtx);
      continue;
    }
    _aDev++;
  }

  if (!_aDev) {
    fprintf(stderr, "No active device: %d\n", _aDev);
    return 1;
  }

  return 0;
}

uint8_t evspot_net_stop(evspot_net_t *pCtx)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)pCtx;
  int _i = 0;
  int numDev = 0;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return 1);

  if ((numDev = tcptrlistnum(_pCtx->devs)) != 0) {
    for (_i = 0; _i < numDev; ++_i) {
      evspot_dev_t *_pDevCtx = tcptrlistval(_pCtx->devs, _i);
      evspot_dev_close(_pDevCtx);
    }
  }

  return 0;
}

uint8_t evspot_net_destroy(evspot_net_t *pCtx)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)pCtx;
  int _i = 0;
  int numDev = 0;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return 1);
 
  if ((numDev = tcptrlistnum(_pCtx->devs)) != 0) {
    for (_i = 0; _i < numDev; ++_i) {
      evspot_dev_t *_pDevCtx = tcptrlistval(_pCtx->devs, _i);
      evspot_dev_free(_pDevCtx);
    }
    tcptrlistclear(_pCtx->devs);
  }

  tcfree(_pCtx);

  return 0;
}

// vim: ts=2:sw=2:expandtab
