#pragma once
#ifndef __EVSIP_CORE_H__
#define __EVSIP_CORE_H__

/**
 * @brief
 */
typedef struct evspot_app_s {
  const char           *major;
  const char           *minor;
  struct event_base    *base;           //!< LibEvent Base loop
  struct event         *evsig;          //!< LibEvent Signal
  evspot_net_t         *net;
  evspot_cfg_t         *cfg;

  const char           *filecfg; 
} evspot_app_t;


extern evspot_app_t pEvspotAppCtx[];

#endif /* __EVSIP_CORE_H__ */

// vim: ts=2:sw=2:expandtab
