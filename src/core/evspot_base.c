#include <stdlib.h>
#include <sys/signal.h>

#include <event2/event.h>
#include <event2/util.h>

#include <evspot_utils.h>
#include <evspot_cfg.h>
#include <evspot_net.h>
#include <evspot_core.h>

struct evspot_app_s pEvspotAppCtx[1] = {{
  .major   = "1",
  .minor   = "0",
  .base    = NULL,
  .evsig   = NULL,
  .net     = NULL,
  .cfg     = NULL,
  .filecfg = "/etc/evspot.cfg",
}};

// vim: ts=2:sw=2:expandtab
