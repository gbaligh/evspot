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
#include <linux/netfilter.h>    
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "../link.h"

#define EVSPOT_NFQUEUE_MAGIC 0x30122016

static int evspot_nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

uint8_t evspot_nfqueue_init(evspot_link_t **ppCtx, const char *name)
{
  struct evspot_nfqueue_s *_pCtx = (struct evspot_nfqueue_s *)0;
 
  _pCtx = (struct evspot_nfqueue_s *)tcmalloc(sizeof(struct evspot_nfqueue_s));
  if (_pCtx == (struct evspot_nfqueue_s *)0) {
    _E("Error memory allocation");
    return 1;
  }
  memset(_pCtx, 0, sizeof(struct evspot_nfqueue_s));

  _pCtx->magic = EVSPOT_NFQUEUE_MAGIC;
  _pCtx->name = name;

  *ppCtx = (evspot_link_t *)_pCtx;

  return 0;
}

uint8_t evspot_nfqueue_start(evspot_link_t *pCtx)
{
  struct evspot_nfqueue_s *_pCtx = (struct evspot_nfqueue_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NFQUEUE_MAGIC, return 1);

  _pCtx->nfq = nfq_open();
  if (_pCtx->nfq == NULL) {
    _E("Error during nfq_open()");
    return 1;
  }

  if (nfq_bind_pf(_pCtx->nfq, AF_INET) < 0) {
    _E("Error during nfq_bind_pf()");
    return 1;
  }

  _pCtx->qh = nfq_create_queue(_pCtx->nfq, 0, &evspot_nfqueue_cb, _pCtx);
  if (_pCtx->qh == NULL) {
    _E("error during nfq_create_queue()");
    return 1;
  }

  if (nfq_set_mode(_pCtx->qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    _E("can't set packet_copy mode\n");
    return 1;
  }

  return 0;
}

uint8_t evspot_nfqueue_getfd(evspot_link_t *pCtx, int *pfd)
{
  struct evspot_nfqueue_s *_pCtx = (struct evspot_nfqueue_s *)pCtx;
  int _fd = -1;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NFQUEUE_MAGIC, return 1);

  _fd = nfq_fd(_pCtx->nfq);

  if (_fd < 0) {
    _D("Invalid file descriptor");
    return 1;
  }

  *pfd = _fd;

  return 0;
}

uint8_t evspot_nfqueue_read(evspot_link_t *pCtx, void *user, void (*cb)(void*,const size_t,const uint8_t*))
{
  struct evspot_nfqueue_s *_pCtx = (struct evspot_nfqueue_s *)pCtx;
  int rv;
  int _fd = -1;
  static char buf[4096] __attribute__ ((aligned));

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NFQUEUE_MAGIC, return 1);

  _fd = nfq_fd(_pCtx->nfq);
  if (_fd < 0) {
    _D("Invalid file descriptor");
    return 1;
  }

  rv = recv(_fd, buf, sizeof(buf), 0);
  if (rv <= 0) {
    _D("No bytes received");
    return 1;
  }

  nfq_handle_packet(_pCtx->nfq, buf, rv);

  if (cb) {
    cb(user, rv, buf);
  }

  return 0;
}

uint8_t evspot_nfqueue_stop(evspot_link_t *pCtx)
{
  struct evspot_nfqueue_s *_pCtx = (struct evspot_nfqueue_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NFQUEUE_MAGIC, return 1);

  nfq_destroy_queue(_pCtx->qh);

  if (nfq_unbind_pf(_pCtx->nfq, AF_INET) < 0) {
    _E("Error during nfq_unbind_pf()");
  }

  nfq_close(_pCtx->nfq);

  return 0;
}

uint8_t evspot_nfqueue_free(evspot_link_t *pCtx)
{
  struct evspot_nfqueue_s *_pCtx = (struct evspot_nfqueue_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NFQUEUE_MAGIC, return 1);

  tcfree(_pCtx);

  return 0;
}

static int evspot_nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
  struct evspot_nfqueue_s *_pCtx = (struct evspot_nfqueue_s *)data;
  uint32_t id;
  struct nfqnl_msg_packet_hdr *ph;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSPOT_NFQUEUE_MAGIC, return 1);

  ph = nfq_get_msg_packet_hdr(nfa);
  id = ntohl(ph->packet_id);

  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

const evspot_link_ops_t nfqueue_ops = {
  .init = evspot_nfqueue_init,
  .start = evspot_nfqueue_start,
  .getfd = evspot_nfqueue_getfd,
  .read = evspot_nfqueue_read,
  .stop = evspot_nfqueue_stop,
  .free = evspot_nfqueue_free,
}; 

// vim: ts=2:sw=2:expandtab
