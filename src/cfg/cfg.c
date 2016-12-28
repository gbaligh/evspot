#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>

#include <stdint.h>

#include <libconfig.h>

#include <event2/event.h>
#include <event2/util.h>

#include <evspot_utils.h>
#include <evspot_cfg.h>

/*
#define CONFIG_TYPE_NONE    0
#define CONFIG_TYPE_GROUP   1
#define CONFIG_TYPE_INT     2
#define CONFIG_TYPE_INT64   3
#define CONFIG_TYPE_FLOAT   4
#define CONFIG_TYPE_STRING  5
#define CONFIG_TYPE_BOOL    6
#define CONFIG_TYPE_ARRAY   7
#define CONFIG_TYPE_LIST    8
*/

#define EVSIP_CFG_MAGIC 0x20161212

struct evspot_cfg_key_s {
  const char *path;
  const int type;
  const int offset;
  const char *description;
};

struct evspot_cfg_s {
  uint32_t magic;
  uint8_t initialized;
  struct evspot_cfg_opt_s *opt;
  config_t cfg[1];
};

struct evspot_cfg_key_s evspot_cfg_keys[] = {
  {"url",         CONFIG_TYPE_STRING, offsetof(struct evspot_cfg_opt_s, url),   
   "UAM server URL to redirect clients to, using HTTP 302."},
  {"interface",   CONFIG_TYPE_STRING, offsetof(struct evspot_cfg_opt_s, intf),  
   "Interface for clients packets."},
};

uint8_t evspot_cfg_help(void)
{
  unsigned int i = 0;
  for (i = 0; i < sizeof(evspot_cfg_keys)/sizeof(evspot_cfg_keys[0]); i++) {
    fprintf(stderr, "%-15s: %s\n", evspot_cfg_keys[i].path, evspot_cfg_keys[i].description);
  }
  return 0;
}

uint8_t evspot_cfg_init(evspot_cfg_t **ppCtx)
{
  struct evspot_cfg_s *_pCtx = (struct evspot_cfg_s *)0;

  _pCtx = (struct evspot_cfg_s *)tcmalloc(sizeof(struct evspot_cfg_s));
  if (_pCtx == (struct evspot_cfg_s *)0) {
    TCDPRINTF("Memory allocation failed.");
    return 1;
  }

  _pCtx->opt = (struct evspot_cfg_opt_s *)tcmalloc(sizeof(struct evspot_cfg_opt_s));
  if (_pCtx->opt == (struct evspot_cfg_opt_s *)0) {
    TCDPRINTF("Memory allocation failed for options");
    tcfree(_pCtx);
    return 1;
  }

  /* default for libevent */
  _pCtx->opt->evopt = event_config_new();
  if (_pCtx->opt->evopt == NULL) {
    TCDPRINTF("Could not create libevent config");
    tcfree(_pCtx->opt);
    tcfree(_pCtx);
    return 1;
  }

  event_config_avoid_method(_pCtx->opt->evopt, "select");

  config_init(_pCtx->cfg);

  _pCtx->magic = EVSIP_CFG_MAGIC;
  _pCtx->initialized = 1;
  *ppCtx = _pCtx;

  return 0;
}

uint8_t evspot_cfg_destroy(evspot_cfg_t *pCtx)
{
  struct evspot_cfg_s *_pCtx = (struct evspot_cfg_s *)pCtx; 

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSIP_CFG_MAGIC, return 1);

  config_destroy(_pCtx->cfg);

  if (_pCtx->opt->evopt != NULL) {
    event_config_free(_pCtx->opt->evopt);
  }

  tcfree(_pCtx->opt);

  tcfree(_pCtx);

  return 0;
}

uint8_t evspot_cfg_load(evspot_cfg_t *pCtx, const char *file)
{
  struct evspot_cfg_s *_pCtx = (struct evspot_cfg_s *)pCtx;
  unsigned int i = 0;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSIP_CFG_MAGIC, return 1);

  if (access(file, R_OK) != 0) {
    TCDPRINTF("File %s not found.", file);
    return 1;
  } 

  if (config_read_file(_pCtx->cfg, file) != CONFIG_TRUE) {
    TCDPRINTF("%s:%d - %s",
        config_error_file(_pCtx->cfg),
        config_error_line(_pCtx->cfg), 
        config_error_text(_pCtx->cfg));
    return 1;
  }

  for (i=0; i<sizeof(evspot_cfg_keys)/sizeof(evspot_cfg_keys[0]); ++i) {
    config_setting_t *setting = NULL;
    struct evspot_cfg_key_s key = evspot_cfg_keys[i];
    setting = config_lookup(_pCtx->cfg, key.path);
    if (setting == NULL) {
      continue;
    }

    if (config_setting_type(setting) != key.type) {
      TCDPRINTF("Not compatible configuration detected");
      return 1;
    }

    switch (key.type) {
      case CONFIG_TYPE_STRING:
        {
          const char *value  = NULL;
          const char **member = (const char **)((char *)_pCtx->opt + key.offset);
          value = config_setting_get_string(setting);
          *member = value;
          TCDPRINTF("[%s = %s]", key.path, *member);
        }
        break;
      default:
        break;
    }
  }

  return 0;
}

evspot_cfg_opt_t *evspot_cfg_get_opt(evspot_cfg_t *pCtx)
{
  struct evspot_cfg_s *_pCtx = (struct evspot_cfg_s *)pCtx;

  EVSPOT_CHECK_MAGIC_CTX(_pCtx, EVSIP_CFG_MAGIC, return NULL);

  if (!_pCtx->initialized) {
    TCDPRINTF("Configuration module not initialized yet !");
    return NULL;
  }

  return (evspot_cfg_opt_t *)_pCtx->opt;
}

// vim: ts=2:sw=2:expandtab:
