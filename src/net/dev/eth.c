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
#include "../link/link.h"
#include "../stack/stack.h"

#define EVSPOT_DEV_MAGIC 0x21432017

struct evspot_dev_s {
  uint32_t magic;
  struct event_base *base;
  struct event *ev;

  evspot_stack_t *stack;
  evspot_link_t *link;

  const char *name;
  uint8_t idx;
  struct in_addr ipv4;
  struct in_addr mask;
  struct in_addr brcst;
  uint32_t mtu;
  uint32_t kflags;
};

static void evspot_dev_event_handler(evutil_socket_t fd, short event, void *arg);

static void evspot_dev_link_handler(void *pCtx, const size_t s, const uint8_t *bytes);

uint8_t evspot_dev_init(evspot_dev_t **ppCtx, const char *name, struct event_base *base)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)0;
  int _fd = -1;

  _pCtx = (struct evspot_dev_s *)tcmalloc(sizeof(struct evspot_dev_s));
  if (_pCtx == (struct evspot_dev_s *)0) {
    return 1;
  }

  memset(_pCtx, 0, sizeof(struct evspot_dev_s));

  /* init stack for this device */
  if (evspot_stack_init(&_pCtx->stack) != 0) {
    TCDPRINTF("Stack init failure for device %s", name);
    tcfree(_pCtx);
    return 1;
  }

  /* init link for this device */
  if (evspot_link_init(&_pCtx->link, EVSPOT_LINK_TYPE_PCAP, name) != 0) {
    TCDPRINTF("Link init failure for device %s", name);
    evspot_stack_free(_pCtx->stack);
    tcfree(_pCtx);
    return 1;
  }
   
  _pCtx->name = name;
  _pCtx->base = base;
  _pCtx->magic = EVSPOT_DEV_MAGIC;
 
  if (evspot_link_getfd(_pCtx->link, &_fd) != 0) {
    TCDPRINTF("Link failure for device %s", name);
    tcfree(_pCtx);
    return 1;
  }

  _pCtx->ev = event_new(_pCtx->base, 
      _fd, 
      EV_READ|EV_PERSIST, 
      evspot_dev_event_handler, 
      _pCtx);

  /* Ok */
  *ppCtx = _pCtx;

  return 0;
}

uint8_t evspot_dev_open(evspot_dev_t *pCtx)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  evspot_link_start(_pCtx->link);

  if (event_add(_pCtx->ev, 0) != 0) {
    TCDPRINTF("Error adding libpcap event");
    return 1;
  }

  return 0;
}

uint8_t evspot_dev_close(evspot_dev_t *pCtx)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  evspot_link_stop(_pCtx->link);

  event_del(_pCtx->ev);

  return 0;
}

uint8_t evspot_dev_free(evspot_dev_t *pCtx)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  evspot_stack_free(_pCtx->stack);

  evspot_link_free(_pCtx->link);

  event_free(_pCtx->ev);

  tcfree(_pCtx);

  return 0;
}

static void evspot_dev_event_handler(evutil_socket_t fd, short event, void *arg)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)arg;
  int _fd = -1;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return);

  evspot_link_getfd(_pCtx->link, &_fd);

  if (fd != _fd) {
    TCDPRINTF("Event from socket(%d) not from %d", fd, _fd);
    return;
  }

  if (event & EV_READ) {
    TCDPRINTF("New READ event detected on device %s", _pCtx->name);
    evspot_link_read(_pCtx->link, _pCtx, evspot_dev_link_handler);
  }
}

static void evspot_dev_link_handler(void *pCtx, const size_t s, const uint8_t *bytes)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;
  
  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return);

  if (s == 0) {
    return;
  }

  if (bytes == NULL) {
    return;
  }
 
  evspot_stack_parse(_pCtx->stack, (uint8_t *)bytes, s);
}

// vim: ts=2:sw=2:expandtab
