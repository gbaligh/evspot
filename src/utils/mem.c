#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <evspot_utils.h>

struct ev_mem {
  uint32_t nrefs;
  ev_mem_destroy_f *df;
};

void *ev_mem_alloc(size_t size, ev_mem_destroy_f *df)
{
  struct ev_mem *_m;
  _m = malloc(sizeof(struct ev_mem) + size);
  if (!_m)
    return (void *)0;
  _m->nrefs = 1;
  _m->df = df;
  return (void *)(_m + 1);
}

void *ev_mem_zalloc(size_t size, ev_mem_destroy_f *df)
{
  void *_p = (void *)0;
  _p = ev_mem_alloc(size, df);
  if (!_p)
    return (void *)0;
  memset(_p, 0, size);
  return _p;
}

void *ev_mem_ref(void *p)
{
  struct ev_mem *_m;
  if (!p)
    return (void *)0;
  _m = ((struct ev_mem *)p) - 1;
  ++_m->nrefs;
  return p;
}

void *ev_mem_unref(void *p)
{
  struct ev_mem *_m = (struct ev_mem *)0;
  if (!p)
    return (void *)0;
  _m = ((struct ev_mem *)p) - 1;
  if (--_m->nrefs > 0)
    return (void *)0;
  if (_m->df)
    _m->df(p);
  if (_m->nrefs > 0)
    return (void *)0;
  free(_m);
  return (void *)0;
}

uint32_t ev_mem_refs(const void *p)
{
  struct ev_mem *_m = (struct ev_mem *)0;
  if (!p)
    return 0;
  _m = ((struct ev_mem *)p) - 1;
  return _m->nrefs;
}

// vim: ts=2:sw=2:expandtab
