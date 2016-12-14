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


uint8_t evspot_net_ipv4_parse(libnet_t *libnet_ctx, uint8_t *raw, size_t raw_len)
{
	struct libnet_ipv4_hdr *hip = NULL;
  uint8_t *n_raw;
  size_t n_size;
  uint8_t with_payload = 1;


  if (raw_len < sizeof(struct libnet_ipv4_hdr)) {
    return 1;
  }

	hip = (struct libnet_ipv4_hdr*)raw;
  n_raw = (raw + sizeof(struct libnet_ipv4_hdr));
  n_size = raw_len - sizeof(struct libnet_ipv4_hdr);

  switch (hip->ip_p) {
    case IPPROTO_TCP:
      with_payload = evspot_net_tcp_parse(libnet_ctx, n_raw, n_size);
      break;

    case IPPROTO_UDP:
      with_payload = evspot_net_udp_parse(libnet_ctx, n_raw, n_size);
      break;

    case IPPROTO_ICMP:
      with_payload = evspot_net_icmpv4_parse(libnet_ctx, n_raw, n_size);
      break;

    default:
      break;
  }

	libnet_build_ipv4(
          ntohs(hip->ip_len),
          hip->ip_tos, 
          ntohs(hip->ip_id), 
          ntohs(hip->ip_off), 
          hip->ip_ttl, 
          hip->ip_p, 
          hip->ip_sum, 
          ntohl(hip->ip_src.s_addr), 
          ntohl(hip->ip_dst.s_addr),
          with_payload?n_raw:0, with_payload?n_size:0, libnet_ctx, 0);

	return 0;
}

// vim: ts=2:sw=2:expandtab
