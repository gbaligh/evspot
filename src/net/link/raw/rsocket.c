#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include <pcap.h> /* TODO: To be remove and stored in the pcap module */
#include <event2/event.h>
#include <event2/util.h>

#include <evspot_utils.h>
#include <evspot_net.h>
#include <linux/netfilter.h>    
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "../link.h"

#define EVSPOT_RSOCK_MAGIC 0x01072017

uint8_t evspot_rsocket_init(evspot_link_t **ppCtx, const char *name)
{
  return 0;
}

uint8_t evspot_rsocket_start(evspot_link_t *pCtx)
{
  return 0;
}

uint8_t evspot_rsocket_getfd(evspot_link_t *pCtx, int *pfd)
{
  return 0;
}

uint8_t evspot_rsocket_read(evspot_link_t *pCtx, void *user, void (*cb)(void*,const size_t,const uint8_t *))
{
  return 0;
}

uint8_t evspot_rsocket_stop(evspot_link_t *pCtx)
{
  return 0;
}

uint8_t evspot_rsocket_free(evspot_link_t *pCtx)
{
  return 0;
}

const evspot_link_ops_t rsocket_ops = {
  .init = evspot_rsocket_init,
  .start = evspot_rsocket_start,
  .getfd = evspot_rsocket_getfd,
  .read = evspot_rsocket_read,
  .stop = evspot_rsocket_stop,
  .free = evspot_rsocket_free,
};
