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
  struct event      *sockev;
  libnet_t          *libnet_ctx;
};

static void evspot_net_dispatcher(evutil_socket_t fd, short event, void *arg);

uint8_t evspot_net_init(struct event_base *pBase, evspot_net_t **pCtx)
{
  struct evspot_net_ctx_s *_pCtx = NULL;
  evutil_socket_t _fd = -1;
  int enable = 1;
  char errbuf[LIBNET_ERRBUF_SIZE];

  if (pBase == NULL) {
    fprintf(stderr, "Event base is NULL\n");
    return 1;
  }

  _pCtx = (struct evspot_net_ctx_s *)malloc(sizeof(struct evspot_net_ctx_s));
  if (_pCtx == NULL) {
    fprintf(stderr, "allocation failed\n");
    return 1;
  }

  memset(_pCtx, 0, sizeof(struct evspot_net_ctx_s));
  
  _pCtx->libnet_ctx = libnet_init(LIBNET_LINK_ADV, "eth1", errbuf);
  if (_pCtx->libnet_ctx == 0) {
    fprintf(stderr, "libnet error: %s\n", errbuf);
    free(_pCtx);
    return 1;
  }

  _fd = libnet_getfd(_pCtx->libnet_ctx);

  /* Enable reception and transmission of broadcast frames */
  setsockopt(_fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable));

  setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

  evutil_make_socket_nonblocking(_fd);
   
  _pCtx->sockev = event_new(pBase, _fd, EV_READ|EV_PERSIST, evspot_net_dispatcher, (void*)_pCtx);
  if (_pCtx->sockev == NULL) {
    fprintf(stderr, "Creating new event failed\n");
    libnet_destroy(_pCtx->libnet_ctx);
    free(_pCtx);
    return 1;
  }

  _pCtx->magic = EVSPOT_NET_CTX_MAGIC;
  _pCtx->base = pBase;
  *pCtx = _pCtx;

  return 0;
}

uint8_t evspot_net_start(evspot_net_t *pCtx)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return 1);

  if (_pCtx->sockev == NULL) {
    fprintf(stderr, "No event created: Context not initialized or destroyed !");
    return 1;
  }
 
  if (event_add(_pCtx->sockev, 0) != 0) {
    fprintf(stderr, "Error adding Ctx(%p)", _pCtx);
    return 1;
  }

  return 0;
}

uint8_t evspot_net_stop(evspot_net_t *pCtx)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return 1);

  if (event_del(_pCtx->sockev) != 0) {
    fprintf(stderr, "Error removing Ctx(%p)", _pCtx);
  }

  return 0;
}

uint8_t evspot_net_destroy(evspot_net_t *pCtx)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return 1);

  event_free(_pCtx->sockev);
  
  _pCtx->sockev = NULL; 

  libnet_destroy(_pCtx->libnet_ctx);

  free(_pCtx);

  return 0;
}


static void evspot_net_dispatcher(evutil_socket_t fd, short event, void *arg)
{
  struct evspot_net_ctx_s *_pCtx = (struct evspot_net_ctx_s *)arg;
  evutil_socket_t _fd = -1;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NET_CTX_MAGIC, return);

  _fd = libnet_getfd(_pCtx->libnet_ctx);

  if (_fd != fd) {
    fprintf(stderr, "not the same socket for Ctx(%p)", _pCtx);
    return;
  }

  if (event & EV_READ) {
    uint8_t buf[LIBNET_MAX_PACKET];
    size_t buf_len = sizeof(buf);
    
    buf_len = recv(_fd, buf, sizeof(buf), 0);
    buf[buf_len] = '\0';

    if (buf_len == 0) {
      return;
    }

    libnet_diag_dump_context(_pCtx->libnet_ctx);
    libnet_clear_packet(_pCtx->libnet_ctx);

    evspot_net_eth_parse(_pCtx->libnet_ctx, buf, buf_len);

    libnet_diag_dump_hex((const uint8_t *)buf, buf_len, 1, stdout);
    libnet_diag_dump_pblock(_pCtx->libnet_ctx);

#if 0
    if ((buf_len > 0) && (_pCtx->callbacks.msg_recv_cb != NULL)) {
      _pCtx->callbacks.msg_recv_cb(_pCtx, buf, buf_len, _pCtx->callbacks.user_data);
    }

    if (_pCtx->callbacks.event_cb != NULL) {
      _pCtx->callbacks.event_cb(_pCtx, 1, 0, _pCtx->callbacks.user_data);
    }
#endif
  }
}


// vim: ts=2:sw=2:expandtab
