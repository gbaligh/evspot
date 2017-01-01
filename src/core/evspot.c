#include <stdlib.h>
#include <sys/signal.h>

#include <event2/event.h>
#include <event2/util.h>

#include <evspot_utils.h>
#include <evspot_cfg.h>
#include <evspot_net.h>
#include <evspot_core.h>

static void evspot_libevent_log_cb(int severity, const char * msg)
{
  NOT_USED(severity);
  TCDPRINTF("[libevent]- %s", msg);
}

static void evspot_libevent_fatal_cb(int err)
{
  TCDPRINTF("FATAL error detected on libevent %d\n", err);
  exit(err);
} 

static void evspot_signal_cb(evutil_socket_t fd, short event, void * arg)
{
  NOT_USED(fd);
  evspot_app_t *_pCtx = (evspot_app_t *)arg;
  TCDPRINTF("\nSignal (%d) ...\n", event);

  (void)event_base_loopexit(_pCtx->base, NULL);
}

static void evspot_tcfatal_cb(const char *msg)
{
  TCDPRINTF("EMERG ERROR FATAL: %s", msg);
}

int main(int argc, char *argv[])
{
  evspot_app_t *_pCtx = pEvspotAppCtx;
  evspot_cfg_opt_t *opts = NULL;
	int ret = EXIT_SUCCESS;

  NOT_USED(argc);
  NOT_USED(argv);

  /* The variable `tcfatalfunc' is the pointer to the call back function for handling a fatal error. */
  tcfatalfunc = evspot_tcfatal_cb;

  /* Init configuration */
  if (evspot_cfg_init(&(_pCtx->cfg)) != 0) {
    TCDPRINTF("Error initializing configuration");
    return EXIT_FAILURE;
  }

  /* Load file */
  if (evspot_cfg_load(_pCtx->cfg, _pCtx->filecfg) != 0) {
    TCDPRINTF("Error loading configuration file");
    goto APPEXIT;
  }

  /* get all options loaded */
  opts = evspot_cfg_get_opt(_pCtx->cfg);
  if (opts == NULL) {
    TCDPRINTF("FATAL: Options not found %p", opts);
    goto APPEXIT;
  }

	/* Set Log callback for libevent */
	event_set_log_callback(evspot_libevent_log_cb);

  /* Handling fatal errors */
  event_set_fatal_callback(evspot_libevent_fatal_cb);

	_pCtx->base = event_base_new_with_config(opts->evopt);
	if (_pCtx->base == NULL) {
    TCDPRINTF("Erro creating libevent pool");
    goto APPEXIT;
	}

	if (event_base_priority_init(_pCtx->base, 2) != 0) {
    TCDPRINTF("Error setting priority for libevent");
	}

	_pCtx->evsig = evsignal_new(_pCtx->base, SIGINT, &evspot_signal_cb, (void *)_pCtx);
	if (_pCtx->evsig == NULL) {
    TCDPRINTF("Error creating Signal handler");
	}

  if (event_priority_set(_pCtx->evsig, 0) != 0) {
    TCDPRINTF("Error setting priority for evnnt");
  }

	if (evsignal_add(_pCtx->evsig, NULL) != 0) {
    TCDPRINTF("Error adding Signal handler into libevent");
	}

  if (evspot_net_init(_pCtx, &_pCtx->net) != 0) {
    TCDPRINTF("Could not start Network stack");
    goto APPEXIT;
  }

  /* Load devices from config */
  if (opts->intf != NULL) {
    if (evspot_net_dev_add(_pCtx->net, opts->intf, EVSPOT_LINK_TYPE_PCAP) != 0) {
      TCDPRINTF("Error adding interface %s", opts->intf);
    }
  }

  if (opts->pcap_file != NULL) {
    if (evspot_net_dev_add(_pCtx->net, opts->pcap_file, EVSPOT_LINK_TYPE_PCAPOFF) != 0) {
      TCDPRINTF("Error Loading file %s", opts->pcap_file);
    }
  }

  if (evspot_net_start(_pCtx->net) != 0) {
    TCDPRINTF("Error in starting Network!");
    goto APPEXIT;
  }

  TCDPRINTF("Start EvSpot");
    
	if (event_base_dispatch(_pCtx->base) != 0) {
    TCDPRINTF("Error starting libevent loop");
    goto APPEXIT;
	}
  TCDPRINTF("Shutting down EvSpot");

  evspot_net_stop(_pCtx->net);

  evspot_net_destroy(_pCtx->net);

APPEXIT:
	/* Free SIG */
  event_free(_pCtx->evsig);
  
  /* Free libEvent */
	event_base_free(_pCtx->base);

  /* Free cfg */  
  evspot_cfg_destroy(_pCtx->cfg);

	return ret;
}

// vim: ts=2:sw=2:expandtab
