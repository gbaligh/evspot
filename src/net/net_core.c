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
#include <evspot_cfg.h>
#include <evspot_net.h>
#include <evspot_core.h>

#define EVSPOT_NET_CTX_MAGIC 0x19820117

struct evspot_net_ctx_s {
  uint32_t              magic;
  struct evspot_app_s   *app;
  TCPTRLIST             *devs;
};

uint8_t evspot_net_init(struct evspot_app_s *pAppCtx, evspot_net_t **ppCtx)
{
  struct evspot_net_ctx_s *_pCtx = NULL;

  if (pAppCtx == NULL) {
    TCDPRINTF("Event base is NULL");
    return 1;
  }

  _pCtx = (struct evspot_net_ctx_s *)tcmalloc(sizeof(struct evspot_net_ctx_s));
  if (_pCtx == NULL) {
    TCDPRINTF("allocation failed");
    return 1;
  }

  memset(_pCtx, 0, sizeof(struct evspot_net_ctx_s));
  
  _pCtx->devs = tcptrlistnew(); 
  if (_pCtx->devs == NULL) {
    TCDPRINTF("Error creating devices list");
    tcfree(_pCtx);
    return 1;
  }

  _pCtx->magic = EVSPOT_NET_CTX_MAGIC;
  _pCtx->app   = pAppCtx;
  *ppCtx = _pCtx;

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
    TCDPRINTF("Error: no device created for network");
    return 1;
  }

  for (_i = 0; _i < numDev; ++_i) {
    evspot_dev_t *_pDevCtx = tcptrlistval(_pCtx->devs, _i);

    if (evspot_dev_open(_pDevCtx) != 0) {
      TCDPRINTF("Error starting device %p", _pDevCtx);
      continue;
    }

    TCDPRINTF("Started capture on device %p", _pDevCtx);
    _aDev++;
  }

  if (!_aDev) {
    TCDPRINTF("No active device: %d", _aDev);
    return 1;
  }

  return 0;
}

uint8_t evspot_net_dev_add(evspot_net_t *pCtx, const char *name)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)pCtx;
  evspot_dev_t *_pDevCtx = NULL;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return 1);

  if (evspot_dev_init(&_pDevCtx, name, _pCtx->app->base) != 0) {
    TCDPRINTF("Error initializing device %s", name);
    return 1;
  }

  TCDPRINTF("New device created (%s:%p)", name, _pDevCtx);

  tcptrlistpush(_pCtx->devs, _pDevCtx);

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
