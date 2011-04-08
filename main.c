/* have a look at "/usr/include/netinet/ether.h" */
/* you can test this program with "wget www.google.fr" */

#define _BSD_SOURCE 1

/* #include <sys/ioctl.h> */
/* #include <sys/socket.h> */
/* #include <sys/stat.h> */
/* #include <sys/types.h> */

/* #include <arpa/inet.h> */
/* #include <net/ethernet.h> */
 
/* #ifdef LINUX */
/* #include <netinet/ether.h> */
/* #endif */
 
#include <netinet/if_ether.h>
/* #include <netinet/in.h> */
#include <netinet/tcp.h> 
/* #include <netinet/udp.h> */
 
/* #include <fcntl.h> */
/* #include <ifaddrs.h> */
#include <netdb.h>
#include <pcap.h>
/* #include <signal.h> */
/* #include <stdio.h> */
#include <stdlib.h>
#include <string.h>
/* #include <syslog.h> */

#define MAX_BYTES2CAPTURE 2048

struct nread_ip {
  u_int8_t        ip_vhl;          /* header length, version */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)

  u_int8_t        ip_tos;          /* type of service           */
  u_int16_t       ip_len;          /* total length              */
  u_int16_t       ip_id;           /* identification            */
  u_int16_t       ip_off;          /* fragment offset field     */
#define IP_DF 0x4000                 /* dont fragment flag        */
#define IP_MF 0x2000                 /* more fragments flag       */
#define IP_OFFMASK 0x1fff            /* mask for fragmenting bits */
  u_int8_t        ip_ttl;          /* time to live              */
  u_int8_t        ip_p;            /* protocol                  */
  u_int16_t       ip_sum;          /* checksum                  */
  struct  in_addr ip_src, ip_dst;  /* source and dest address   */
};

struct nread_tcp {
  u_short th_sport; /* source port            */
  u_short th_dport; /* destination port       */
  tcp_seq th_seq;   /* sequence number        */
  tcp_seq th_ack;   /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int th_x2:4,    /* (unused)    */
    th_off:4;         /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
  u_int th_off:4,   /* data offset */
    th_x2:4;          /* (unused)    */
#endif
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

static char* substring(const char* str, size_t begin, size_t len)
{
  if (str == 0 || strlen(str) == 0 || strlen(str) < begin || strlen(str) < (begin+len))
    return 0;

  return strndup(str + begin, len);
} 

u_int16_t ethernet_handler (u_char *args, const struct pcap_pkthdr* pkthdr,
			    const u_char* packet)
{
  u_int caplen = pkthdr->caplen; /* length of portion present from bpf  */
  u_int length = pkthdr->len;    /* length of this packet off the wire  */
  struct ether_header *eptr;     /* net/ethernet.h                      */
  u_int ether_type;            /* the type of packet (we return this) */
  eptr = (struct ether_header *) packet;

  if (caplen < 14)
    {
      fprintf(stderr,"Packet length is less than header length\n");
      return -1;
    }

  ether_type = ntohs(eptr->ether_type);
/*   fprintf(stdout,"eth: "); */
/*   fprintf(stdout, */
/* 	  "%s ", (char*) ether_ntoa((struct ether_addr*)eptr->ether_shost)); */
/*   fprintf(stdout, */
/* 	  "%s ", (char*) ether_ntoa((struct ether_addr*)eptr->ether_dhost)); */
 
/*   if (ether_type == ETHERTYPE_IP) { */
/*     fprintf(stdout,"(ip)"); */
/*   } else  if (ether_type == ETHERTYPE_ARP) { */
/*     fprintf(stdout,"(arp)"); */
/*   } else  if (eptr->ether_type == ETHERTYPE_REVARP) { */
/*     fprintf(stdout,"(rarp)"); */
/*   } else { */
/*     fprintf(stdout,"(?)"); */
/*   } */
 
/*   fprintf(stdout," %d\n",length); /\* print len *\/ */
 
  return ether_type;
}

u_char* ip_handler (u_char *args,const struct pcap_pkthdr* pkthdr,
		    const u_char* packet)
{
  const struct nread_ip* _ip;   /* packet structure         */
  const struct nread_tcp* tcp; /* tcp structure            */
  u_int length = pkthdr->len;  /* packet header length  */
  u_int hlen, off, version;             /* offset, version       */
  int len;                        /* length holder         */

  char* dataStr = 0;
  int i = 0;
  u_char* data = 0;
  u_int dataLength = 0;

  /* _ip = (struct nread_ip*)(packet + sizeof(struct ether_header)); */
  /* hlen    = IP_HL(_ip);         /\* get header length *\/ */
  /* length -= sizeof(struct ether_header); */
  tcp = (struct nread_tcp*)(packet + sizeof(struct ether_header) +
  			    sizeof(struct nread_ip));

  //TODO: isReceivablePage(header,sizeofcontent...);
  // which performs a lot of work: is the http content valid? not already seen?
  // or even is the program not checking too many pages at the same time (load
  // balancing system the drops tcp frames if too much work)
  // for now let's consider all web pages used for unit tests are ok (so,
  // be careful with tests)
  //
  // push flag set to 1 to warn its the end of the file that is being transferred
  //
  // looking at ISN/SYN number may also be pertinent
  // http://www.tcpipguide.com/free/t_TCPConnectionEstablishmentSequenceNumberSynchroniz.htm
  // check ip_off from ip structure in ipfilter function to check for fragment/don't fragment value
  // update>>>> do some hand tests to inspect those flags respective roles


  /* len     = ntohs(_ip->ip_len); /\* get packer length *\/ */
  /* version = IP_V(_ip);          /\* get ip version    *\/ */

  /* off = ntohs(_ip->ip_off); */

  /* /\* if (hlen < 5 ) *\/ */
  /* /\*   fprintf(stderr,"Alert: %s bad header length %d\n", inet_ntoa(ip->ip)); *\/ */
  /*     /\* if (ipHeader->ip_p == IPPROTO_TCP) { *\/ */
  /*     /\* 	tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip)); *\/ */
  /*     /\* 	sourcePort = ntohs(tcpHeader->source); *\/ */
  /*     /\* 	destPort = ntohs(tcpHeader->dest); *\/ */
  data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct nread_ip) + sizeof(struct tcphdr));
  dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct nread_ip) + sizeof(struct tcphdr));


  dataStr = (char*) malloc(dataLength * sizeof(char) + 1);
  dataStr[dataLength] = '\0';
  memcpy(dataStr, data, dataLength);

  // convert non-printable characters, other than carriage return, line feed,
  // or tab into periods when displayed.
  for (i = 0; i < dataLength; i++) {
    if ((data[i] < 32 || data[i] > 126) && data[i] != '\0' && data[i] != 10 && data[i] != 11 && data[i] != 13)
      dataStr[i] = '.';
  }

  printf("XXXXpayload preview: (length=%u) %sEOP YYYYYYY\n\n", dataLength, dataStr);
  

/* /\*   if (length < len) *\/ */
/* /\*     fprintf(stderr,"Alert: ip packet truncated: %d bytes missing.\n", len - length); *\/ */

/* /\*   if ((off & 0x1fff) == 0 ) /\\* aka no 1's in first 13 bits *\\/ *\/ */
/* /\*     { *\/ */
      /* fprintf(stdout,"ip: "); */
      /* fprintf(stdout,"%s:%u->%s:%u ", */
      /* 	      (char*)inet_ntoa(_ip->ip_src), tcp->th_sport, */
      /* 	      (char*) inet_ntoa(_ip->ip_dst), tcp->th_dport); */
      /* fprintf(stdout, */
      /* 	      "tos %u len %u off %u ttl %u prot %u cksum %u ", */
      /* 	      _ip->ip_tos, len, off, _ip->ip_ttl, */
      /* 	      _ip->ip_p, _ip->ip_sum); */

  fprintf(stdout,"gotcha tcp frame:\n Source Port:\t%u\n Destination Port: %u\n Sequence Number: %u\n acknowledgment number: %u\n Data Offset: %u\n Flags: %X\n Window: %u\n Checksum: %u\n Urgent Pointer: %u\n",
	  tcp->th_sport, tcp->th_dport, tcp->th_seq, tcp->th_ack, tcp->th_off, tcp->th_flags, tcp->th_win, tcp->th_sum, tcp->th_urp);

  printf("urg=%u ", (tcp->th_flags & TH_URG)>>5);
  printf("ack=%u ", (tcp->th_flags & TH_ACK)>>4);
  printf("psh=%u ", (tcp->th_flags & 8)/*TH_PSH*/>>3);
  printf("rst=%u ", (tcp->th_flags & TH_RST)>>2);
  printf("syn=%u ", (tcp->th_flags & TH_SYN)>>1);
  printf("fin=%u\n\n", (tcp->th_flags & TH_FIN));
  //TODO: discard tcp frames with syn set to 1, discard frames with non http...200 OK

  return NULL;
}

void processPacket(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  int* counter = (int*) args;

  ++*counter;
  printf("---------------------------------Pac.numb%u\n", *counter);
  u_int16_t type = ethernet_handler(args, pkthdr, packet);

  if (type == ETHERTYPE_IP) {
    ip_handler(args, pkthdr, packet);
  } else if (type == ETHERTYPE_ARP) {
    /* noop */
  } else if (type == ETHERTYPE_REVARP) {
    /* noop */
  }
}

int main()
{
  int count = 0;
  pcap_t* descr = 0;			/* Session descr */
  char* device = 0;
  bpf_u_int32 mask;			/* Our netmask */
  bpf_u_int32 net;			/* Our IP address */
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;

  memset(errbuf, 0, PCAP_ERRBUF_SIZE);

  if (getuid()) {
    printf("Error! Must be root ... exiting\n");
    return 1;
  }
  
  device = pcap_lookupdev(errbuf);
  if (device == NULL) {
    printf("%s\n", errbuf);
    return 1;
  }

  descr = pcap_open_live(device, MAX_BYTES2CAPTURE, 0, 512, errbuf);
  if( descr == NULL )
    {
      fprintf(stderr, "error during pcap_open_live: %s\n", errbuf);
      return 1;
    }

  /*ascertain*/
  pcap_lookupnet(device, &net, &mask, errbuf);
/* todo MYIP below */

  /* port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354 */
/* and not src net 192.168 */
/* not broadcast and not multicast */
/* - Matching any TCP traffic with a source port > 1024 */
/* # tcpdump -i eth1 'tcp[0:2] > 1024' */

  /* GET / HTTP/1.1\r\n */
  /* can filter only some of the first 4 datas: (get.)tcpdump -i eth1 'tcp[20:4] = 0x47455420' */
/*or, int the same idea:  ether[100] == 123 and ether[102] == 124 */
  /* char* filter_exp = "tcp[20:4] = 0x47455420"; *///not suitable for pages sent in several pieces (1st part of page will contain the "GET HTTP" things, but rest of the parts won't, but we need them)
  /* char* filter_exp = "tcp and src port 80"; */
  char* filter_exp = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
  if( (pcap_compile(descr, &filter, filter_exp, 1, mask)) == -1)
    {
      fprintf(stderr, "error during 'pcap compile'\n");
      return 1;
    }

  if( (pcap_setfilter(descr, &filter)) == -1)
    {
      fprintf(stderr, "error during 'pcap setfilter'\n");
      return 1;
    }

  pcap_loop(descr, -1, processPacket, (u_char*)&count);
  
  return 0;
}


/* RFC793 for the TCP specification. */
/* RFC1122 for the TCP requirements and a description of the Nagle algorithm. */
/* RFC1323 for TCP timestamp and window scaling options. */
/* RFC1644 for a description of TIME_WAIT assasination hazards. */
/* RFC2481 for a description of Explicit Congestion Notification. */
/* RFC2581 for TCP congestion control algorithms. */
/* RFC2018 and RFC2883 for SACK and extensions to SACK.  */
