#define _BSD_SOURCE 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <evspot_utils.h>
#include <evspot_net.h>

uint8_t evspot_net_icmpv4_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len)
{
  struct libnet_icmpv4_hdr *h = NULL;
  uint8_t *n_raw;
  size_t n_size;
  uint8_t with_payload = 1;

  NOT_USED(libnet_ctx);
  NOT_USED(with_payload);
  
  if (raw_len < sizeof(struct libnet_icmpv4_hdr)) {
    return 1;
  }

  h = (struct libnet_icmpv4_hdr*)raw;
  n_raw = (raw + sizeof(struct libnet_icmpv4_hdr));
  n_size = raw_len - sizeof(struct libnet_icmpv4_hdr);
  
  NOT_USED(n_size);
  NOT_USED(n_raw);
  NOT_USED(h);


/*  libnet_build_udp(
      ntohs(hudp->uh_sport), 
      ntohs(hudp->uh_dport), 
      ntohs(hudp->uh_ulen), 
      ntohs(hudp->uh_sum),
      with_payload?n_raw:0, with_payload?n_size:0, libnet_ctx, 0);*/

  return 0;
}




// vim: ts=2:sw=2:expandtab
