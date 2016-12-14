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

uint8_t evspot_net_tcp_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len)
{
  struct libnet_tcp_hdr *htcp = NULL;
  uint8_t *n_raw;
  size_t n_size;
  uint8_t with_payload = 1;


  if (raw_len < sizeof(struct libnet_tcp_hdr)) {
    return 1;
  }

  htcp = (struct libnet_tcp_hdr*)raw;
  n_raw = (raw + sizeof(struct libnet_tcp_hdr));
  n_size = raw_len - sizeof(struct libnet_tcp_hdr);


  libnet_build_tcp(
      ntohs(htcp->th_sport), 
      ntohs(htcp->th_dport), 
      ntohl(htcp->th_seq), 
      ntohl(htcp->th_ack),
      htcp->th_flags,
      ntohs(htcp->th_win),
      ntohs(htcp->th_sum),
      ntohs(htcp->th_urp),
      n_size,
      with_payload?n_raw:0, with_payload?n_size:0, libnet_ctx, 0);

	return 0;
}

// vim: ts=2:sw=2:expandtab
