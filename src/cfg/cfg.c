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

struct evspot_cfg_key_s {
  const char *path;
  const int type;
  const int offset;
  const char *description;
};

struct evspot_cfg_s {
  uint32_t magic;
  config_t cfg[1];  
  uint8_t initialized;
  struct evspot_cfg_opt_s opt[1];
};

struct evspot_cfg_key_s evspot_cfg_keys[] = {
  {"url",         CONFIG_TYPE_STRING, offsetof(struct evspot_cfg_opt_s, url),   
   "UAM server URL to redirect clients to using HTTP 302."},
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

  _pCtx = (struct evspot_cfg_s *)malloc(sizeof(struct evspot_cfg_s));
  if (_pCtx == (struct evspot_cfg_s *)0) {
    fprintf(stderr, "Memory allocation failed.\n");
    return 1;
  }

  /* default for libevent */
  _pCtx->opt->evopt = event_config_new();
  if (_pCtx->opt->evopt == NULL) {
    fprintf(stderr, "Could not create libevent config\n");
  }

//  event_config_avoid_method(_pCtx->opt->evopt, "select");

  config_init(_pCtx->cfg);

  config_set_tab_width(_pCtx->cfg, 2);
  _pCtx->initialized = 1;

  *ppCtx = _pCtx;

  return 0;
}

uint8_t evspot_cfg_destroy(evspot_cfg_t *pCtx)
{
  struct evspot_cfg_s *_pCtx = (struct evspot_cfg_s *)pCtx;

  if (_pCtx->opt->evopt != NULL) {
    event_config_free(_pCtx->opt->evopt);
  }

  config_destroy(_pCtx->cfg);

  free(_pCtx);

  return 0;
}

uint8_t evspot_cfg_load(evspot_cfg_t *pCtx, const char *file)
{
  struct evspot_cfg_s *_pCtx = (struct evspot_cfg_s *)pCtx;
  config_t *cfg = _pCtx->cfg;
  unsigned int i = 0;

  if (access(file, R_OK | W_OK) != 0) {
    fprintf(stderr, "File %s not found.\n", file);
    return 1;
  } 

  if (config_read_file(cfg, file) == 0) {
    fprintf(stderr, "%s:%d - %s\n",
        config_error_file(cfg),
        config_error_line(cfg), 
        config_error_text(cfg));
    return 1;
  }

  for (i=0; i<sizeof(evspot_cfg_keys)/sizeof(evspot_cfg_keys[0]); ++i) {
    struct evspot_cfg_key_s key = evspot_cfg_keys[i];
    switch (key.type) {
      case CONFIG_TYPE_STRING:
        {
          const char *value  = NULL;
          const char **member = (const char **)((char *)_pCtx->opt + key.offset);
          if (config_lookup_string(cfg, key.path, &value) != 0) {
            *member = value;
            fprintf(stderr, "[%s = %s]\n", key.path, *member);
          }
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

  return _pCtx->opt;
}

// vim: ts=2:sw=2:expandtab:
