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

uint8_t evspot_net_udp_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len)
{
  struct libnet_udp_hdr *hudp = NULL;
  uint8_t *n_raw;
  size_t n_size;
  uint8_t with_payload = 1;

  if (raw_len < sizeof(struct libnet_udp_hdr)) {
    return 1;
  }

  hudp = (struct libnet_udp_hdr*)raw;
  n_raw = (raw + sizeof(struct libnet_udp_hdr));
  n_size = raw_len - sizeof(struct libnet_udp_hdr);


  _I("UDP packet (sport %d)->(dport %d)\n", ntohs(hudp->uh_sport), ntohs(hudp->uh_dport));

  libnet_build_udp(
      ntohs(hudp->uh_sport), 
      ntohs(hudp->uh_dport), 
      ntohs(hudp->uh_ulen), 
      ntohs(hudp->uh_sum),
      with_payload?n_raw:0, with_payload?n_size:0, libnet_ctx, 0);

  return 0;
}

// vim: ts=2:sw=2:expandtab
