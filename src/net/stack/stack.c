#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <evspot_utils.h>
#include <evspot_net.h>
#include "stack.h"

uint8_t evspot_stack_init(evspot_stack_t **ppCtx)
{
  struct evspot_stack_s *_pCtx = (struct evspot_stack_s *)0;

  _pCtx = (struct evspot_stack_s *)tcmalloc(sizeof(struct evspot_stack_s));
  if (_pCtx == (struct evspot_stack_s *)0) {
    TCDPRINTF("Error allocation\n");
    return 1;
  }
  memset(_pCtx, 0, sizeof(struct evspot_stack_s));

  *ppCtx =_pCtx; 

  return 0;
}

uint8_t evspot_stack_parse(evspot_stack_t *pCtx, uint8_t *raw, size_t raw_len)
{
  struct evspot_stack_s *_pCtx = (struct evspot_stack_s *)pCtx;

  _pCtx->raw = raw;
  _pCtx->raw_len = raw_len;
  _pCtx->payload = raw;
  _pCtx->payload_len = raw_len;

  evspot_stack_eth(_pCtx);

  return 0;
}

uint8_t evspot_stack_free(evspot_stack_t *pCtx)
{
  struct evspot_stack_s *_pCtx = (struct evspot_stack_s *)pCtx;

  tcfree(_pCtx);

  return 0;
}

// vim: ts=2:sw=2:expandtab
