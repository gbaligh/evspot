#pragma once
#ifndef __EVSIP_UTL_H__
#define __EVSIP_UTL_H__

#include <tcutil.h>

#define ASSERT(_c_) 

#define NOT_USED(_v_) if (_v_) {}

#define EVSPOT_CHECK_CTX(__CTX__, __CMD__) \
  do { \
    if (__CTX__ == NULL) { \
      fprintf(stderr, "NULL context\n"); \
      ASSERT(0); \
      __CMD__; \
    } \
  } while(0) 

#define EVSPOT_CHECK_MAGIC(__CTX__, __MAGIC__, __CMD__) \
  do { \
    if ((__CTX__)->magic != (__MAGIC__)) { \
      fprintf(stderr, "magic check error %p(%d) inspected %d\n", __CTX__, (__CTX__)->magic, __MAGIC__); \
      ASSERT(0); \
      __CMD__; \
    } \
  } while(0) 

#define EVSPOT_CHECK_MAGIC_CTX(__CTX__, __MAGIC__, __CMD__) \
  do { \
    EVSPOT_CHECK_CTX((__CTX__), __CMD__); \
    EVSPOT_CHECK_MAGIC((__CTX__), (__MAGIC__), __CMD__); \
  } while(0)

#endif /* __EVSIP_UTL_H__ */

// vim: ts=2:sw=2:expandtab
