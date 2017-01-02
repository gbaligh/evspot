#pragma once
#ifndef __EVSIP_UTL_H__
#define __EVSIP_UTL_H__

#include <assert.h>
#include <tcutil.h>

#ifdef DEBUG
#define _D(...) \
do { \
  fprintf(stderr, "%s:%s(%d): ", __FILE__, __func__, __LINE__); \
  fprintf(stderr, __VA_ARGS__); \
  fprintf(stderr, "\n"); \
} while (0)  

#define _I(...) \
do { \
  fprintf(stderr, "%s:%s(%d): ", __FILE__, __func__, __LINE__); \
  fprintf(stderr, __VA_ARGS__); \
  fprintf(stderr, "\n"); \
} while(0)

#define _E(...) \
do { \
  fprintf(stderr, "%s:%s(%d): ", __FILE__, __func__, __LINE__); \
  fprintf(stderr, "[ERROR]"); \
  fprintf(stderr, __VA_ARGS__); \
  fprintf(stderr, "\n"); \
} while(0)

#define ASSERT(_c_) assert((_c_))

#else

#define _D(...)
#define _I(...) \
do { \
  fprintf(stderr, __VA_ARGS__); \
  fprintf(stderr, "\n"); \
} while(0)
#define _E(...) \
do { \
  fprintf(stderr, "[ERROR]"); \
  fprintf(stderr, __VA_ARGS__); \
  fprintf(stderr, "\n"); \
} while(0)

#define ASSERT(_c_) 

#endif /* DEBUG */

#define NOT_USED(_v_) if (_v_) {}

#define EVSPOT_CHECK_CTX(__CTX__, __CMD__) \
  do { \
    if (__CTX__ == NULL) { \
      _E("NULL context\n"); \
      ASSERT(0); \
      __CMD__; \
    } \
  } while(0) 

#define EVSPOT_CHECK_MAGIC(__CTX__, __MAGIC__, __CMD__) \
  do { \
    if ((__CTX__)->magic != (__MAGIC__)) { \
      _E("magic check error %p(%d) inspected %d\n", __CTX__, (__CTX__)->magic, __MAGIC__); \
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
