#pragma once
#ifndef __EVSIP_CFG_H__
#define __EVSIP_CFG_H__

typedef struct evspot_cfg_s evspot_cfg_t;

typedef struct evspot_cfg_opt_s {
  struct event_config  *evopt; 
  const char *intf;
  const char *url;
} evspot_cfg_opt_t;

uint8_t evspot_cfg_help(void);

uint8_t evspot_cfg_init(evspot_cfg_t **ppCtx);

uint8_t evspot_cfg_destroy(evspot_cfg_t *pCtx);

uint8_t evspot_cfg_load(evspot_cfg_t *pCtx, const char *file);

evspot_cfg_opt_t *evspot_cfg_get_opt(evspot_cfg_t *pCtx);

#endif /* __EVSIP_CFG_H__ */

// vim: ts=2:sw=2:expandtab
