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
  uint32_t index;
  struct in_addr ipv4;
  struct in_addr mask;
  struct in_addr broadaddr;
  uint32_t mtu;
  uint16_t flags;
};

static void evspot_dev_event_handler(evutil_socket_t fd, short event, void *arg);

static void evspot_dev_link_handler(void *pCtx, const size_t s, const uint8_t *bytes);

uint8_t evspot_dev_init(evspot_dev_t **ppCtx, const char *name, const uint32_t type, struct event_base *base)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)0;
  int _fd = -1;
  struct ifreq ifr;
  uint32_t linktype = type;

  _pCtx = (struct evspot_dev_s *)tcmalloc(sizeof(struct evspot_dev_s));
  if (_pCtx == (struct evspot_dev_s *)0) {
    return 1;
  }

  memset(_pCtx, 0, sizeof(struct evspot_dev_s));

  /* init stack for this device */
  if (evspot_stack_init(&_pCtx->stack) != 0) {
    _E("Stack init failure for device %s", name);
    tcfree(_pCtx);
    return 1;
  }

  /* init link for this device */
  if (evspot_link_init(&_pCtx->link, linktype, name) != 0) {
    _E("Link init failure for device %s", name);
    evspot_stack_free(_pCtx->stack);
    tcfree(_pCtx);
    return 1;
  }

  _pCtx->name = name;
  _pCtx->base = base;
  _pCtx->magic = EVSPOT_DEV_MAGIC;

  if (linktype != EVSPOT_LINK_TYPE_PCAPOFF) {
    _fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (_fd < 0) {
      _E("Error reading socket for device %s", _pCtx->name);
    } else {
      ifr.ifr_addr.sa_family = AF_INET;
      strncpy(ifr.ifr_name, _pCtx->name, IFNAMSIZ-1);
      ioctl(_fd, SIOCGIFADDR, &ifr); 
      _pCtx->ipv4 = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
      ioctl(_fd, SIOCGIFNETMASK, &ifr);
      _pCtx->mask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr;
      ioctl(_fd, SIOCGIFBRDADDR, &ifr);
      _pCtx->broadaddr = ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_addr;
      ioctl(_fd, SIOCGIFMTU, &ifr);
      _pCtx->mtu = ifr.ifr_mtu;
      ioctl(_fd, SIOCGIFFLAGS, &ifr);
      _pCtx->flags = ifr.ifr_flags;
      ioctl(_fd, SIOCGIFINDEX, &ifr);
      _pCtx->index = ifr.ifr_ifindex;
      close(_fd);
    }

    _D("Device %s[index:%d]", _pCtx->name, _pCtx->index); 
    _D("Device %s[IPv4:%s]", _pCtx->name, inet_ntoa(_pCtx->ipv4));
    _D("Device %s[Mask:%s]", _pCtx->name, inet_ntoa(_pCtx->mask)); 
    _D("Device %s[Broad:%s]", _pCtx->name, inet_ntoa(_pCtx->broadaddr)); 
    _D("Device %s[MTU:%d]", _pCtx->name, _pCtx->mtu);
    _D("Device %s[FLAGS:0x%4X]", _pCtx->name, _pCtx->flags);
  }

  /* Ok */
  *ppCtx = _pCtx;

  return 0;
}

uint8_t evspot_dev_open(evspot_dev_t *pCtx)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;
  struct timeval  tv[1] = {{1, 0}};
  int _fd = -1;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);
 
  evspot_link_start(_pCtx->link);

  if (evspot_link_getfd(_pCtx->link, &_fd) != 0) {
    _E("Link failure for device %s", _pCtx->name);
    return 1;
  }

  _pCtx->ev = event_new(_pCtx->base, _fd, EV_READ|EV_PERSIST, evspot_dev_event_handler, _pCtx);
  if (_pCtx->ev == NULL) {
    _E("Error creating event");
    return 1;
  }

  if (event_priority_set(_pCtx->ev, 1) != 0) {
    _E("Error setting priority for event");
  }

  if (event_add(_pCtx->ev, tv) != 0) {
    _E("Error adding libpcap event");
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

  event_free(_pCtx->ev);

  return 0;
}

uint8_t evspot_dev_free(evspot_dev_t *pCtx)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return 1);

  evspot_stack_free(_pCtx->stack);

  evspot_link_free(_pCtx->link);

  tcfree(_pCtx);

  return 0;
}

static void evspot_dev_event_handler(evutil_socket_t fd, short event, void *arg)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)arg;
  int _fd = -1;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return);

  if (evspot_link_getfd(_pCtx->link, &_fd) != 0) {
    _E("Getting file descriptor from link");
    return;
  }

  if (fd != _fd) {
    _E("Event from socket(%d) not from %d", fd, _fd);
    return;
  }

  if (event & EV_READ) {
    if (evspot_link_read(_pCtx->link, _pCtx, evspot_dev_link_handler) != 0) {
      _E("Read from link");
      return;
    }
  }
}

static void evspot_dev_link_handler(void *pCtx, const size_t s, const uint8_t *bytes)
{
  struct evspot_dev_s *_pCtx = (struct evspot_dev_s *)pCtx;
  
  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_DEV_MAGIC, return);

  if (s == 0) {
    _D("Zero packet size");
    return;
  }

  evspot_stack_parse(_pCtx->stack, (uint8_t *)bytes, s);
}

// vim: ts=2:sw=2:expandtab
