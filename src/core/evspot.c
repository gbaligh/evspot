#include <stdlib.h>
#include <sys/signal.h>

#include <event2/event.h>
#include <event2/util.h>

#include <evspot_utils.h>
#include <evspot_cfg.h>
#include <evspot_net.h>

/**
 * @brief
 */
typedef struct app_s {
  struct event_base    *base;           //!< LibEvent Base loop
  struct event         *evsig;          //!< LibEvent Signal
  evspot_net_t         *net;
  evspot_cfg_t         *cfg;
} app_t;


static void evspot_libevent_log_cb(int severity, const char * msg)
{
  NOT_USED(severity);

  fprintf(stderr, "[libevent]- %s", msg);
}

static void evspot_libevent_fatal_cb(int err)
{
  fprintf(stderr, "FATAL error detected on libevent %d\n", err);
  fflush(stderr);
  exit(err);
} 

static void evspot_signal_cb(evutil_socket_t fd, short event, void * arg)
{
  NOT_USED(fd);

  app_t *ctx = (app_t *)arg;

  fprintf(stderr, "\nSignal (%d) ...\n", event);

  (void)event_base_loopexit(ctx->base, NULL);
}

int main(int argc, char *argv[])
{
	app_t ctx;
  evspot_cfg_opt_t *opts = NULL;
	int ret = EXIT_SUCCESS;

  NOT_USED(argc);
  NOT_USED(argv);

  /* Init configuration */
  if (evspot_cfg_init(&(ctx.cfg)) != 0) {
    fprintf(stderr, "Error initializing configuration\n");
    return 255;
  }

  /* Load file */
  if (evspot_cfg_load(ctx.cfg, "/tmp/evspot.cfg") != 0) {
    fprintf(stderr, "Error loading configuration file\n");
  }

  /* get all options loaded */
  opts = evspot_cfg_get_opt(ctx.cfg);
  if (opts == NULL) {
    fprintf(stderr, "FATAL: Options not found %p\n", opts);
    return 255;
  }

	/* Set Log callback for libevent */
	event_set_log_callback(evspot_libevent_log_cb);

  /* Handling fatal errors */
  event_set_fatal_callback(evspot_libevent_fatal_cb);

	ctx.base = event_base_new_with_config(opts->evopt);
	if (ctx.base == NULL) {
    fprintf(stderr, "Erro creating libevent pool\n");
    return 255;
	}

	if (event_base_priority_init(ctx.base, 2) != 0) {
    fprintf(stderr, "Error setting priority for libevent\n");
	}

	ctx.evsig = evsignal_new(ctx.base, SIGINT, &evspot_signal_cb, (void *)&ctx);
	if (ctx.evsig == NULL) {
    fprintf(stderr, "Error creating Signal handler\n");
	}

	if (evsignal_add(ctx.evsig, NULL) != 0) {
    fprintf(stderr, "Error adding Signal handler into libevent\n");
	}

  if (evspot_net_init(ctx.base, &ctx.net) != 0) {
    fprintf(stderr, "Could not start Network stack\n");
    goto APPEXIT;
  }

  /* Load devices */
  if (evspot_net_devadd(ctx.net, opts->intf) != 0) {
    fprintf(stderr, "Error adding interface %s\n", opts->intf);
  }

  if (evspot_net_start(ctx.net) != 0) {
    fprintf(stderr, "Error in starting Network!\n");
    goto APPEXIT;
  }

  fprintf(stdout, "Start EvSpot\n");
	if (event_base_dispatch(ctx.base) != 0) {
    fprintf(stderr, "Error starting libevent loop\n");
    goto APPEXIT;
	}
  fprintf(stdout, "Shutting down EvSpot\n");

  evspot_net_stop(ctx.net);

  evspot_net_destroy(ctx.net);

APPEXIT:
	/* Free SIG */
  event_free(ctx.evsig);
  
  /* Free libEvent */
	event_base_free(ctx.base);

  /* Free cfg */  
  evspot_cfg_destroy(ctx.cfg);

	return ret;
}

// vim: ts=2:sw=2:expandtab
