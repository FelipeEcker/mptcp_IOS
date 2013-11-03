//
//  Core.h
//  Mptcp
//
//  Created by Felipe Ecker on 17/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#ifndef Mptcp_Core_h
#define Mptcp_Core_h

#define VERSION "2.0.2"

#import "stdio.h"
#import "stdlib.h"
#import "string.h"
#import "unistd.h"
#import "netdb.h"
#import "fcntl.h"
#import "signal.h"
#import "time.h"
#import "termios.h"
#import "ctype.h"
#import "sys/socket.h"
#import "sys/ioctl.h"
#import "netinet/in.h"
#import "arpa/inet.h"
#import "ifaddrs.h"
#import "net/bpf.h"
#import "pcap.h"
#import "sys/uio.h"
#import "netinet/in_systm.h"
#import "net/if.h"
#import "net/if_dl.h"
#import "net/if_types.h"
#import "netinet/ip.h"
#import "netinet/ip_icmp.h"
#import "netinet/tcp.h"
#import "netinet/udp.h"

#define uchar           unsigned char
#define uint8           u_int8_t
#define uint16          u_int16_t
#define uint32          u_int32_t
#define uint64          u_int64_t

#ifdef true
   #undef true
#endif
#ifdef false
   #undef false
#endif
#define true            1
#define false           0
#define ERR             false
#define TLIMIT          1000
#define SLIMIT          TLIMIT * 3

#define SIZE_IP         0x14   /* sizeof(struct iphdr)    - 20 bytes   */
#define SIZE_ICMP       0x08   /* sizeof(struct icmphdr)  - 08 bytes   */
#define SIZE_UDP        0x08   /* sizeof(struct udphdr)   - 08 bytes   */
#define SIZE_TCP        0x14   /* sizeof(struct tcphdr)   - 20 bytes   */
#define SIZE_AUX        0x0C   /* size of auxtcp header   - 12 bytes   */
#define SIZE_ETH        0x0E   /* size of ether_header    - 14 bytes   */

#define __WEB_MODE__    0x01
#define __ICMP_MODE__   0x02
#define __UDP_MODE__    0x04
#define __TCP_MODE__    0x08
#define __ARP_MODE__    0x10
#define __IRC_MODE__    0x20

#define ETH_ARP         0x0806
#define ETH_RARP        0x8035
#define ETH_ARPREQ      0x0001
#define ETH_ARPREPLY    0x0002
#define ETH_RARPREQ     0x0003
#define ETH_RARPREPLY   0x0004
#define ETH_LEN         0x12
#define IP_LEN          0x10

#define TCP_FIN         0x00000001
#define TCP_SYN         0x00000002
#define TCP_RST         0x00000004
#define TCP_PSH         0x00000008
#define TCP_ACK         0x00000010
#define TCP_URG         0x00000020
#define TCP_NULL        0x00000040
#define TCP_CON         0x00000080
#define ICMP_INFO       0x00000100
#define ICMP_TIME_REQ   0x00000200
#define ICMP_ECHO_REQ   0x00000400
#define ICMP_ECHO_REPLY 0x00000800
#define ICMP_MASK_REQ   0x00001000
#define ICMP_MASK_REPLY 0x00002000
#define ICMP_SRC_QUENCH 0x00004000
#define ARP_PING        0x00008000
#define ARP_FLOOD       0x00010000
#define ARP_CANNON      0x00020000
#define WEB_UDP         0x00040000
#define WEB_TCP         0x00080000
#define WEB_HTTP        0x00100000
#define WEB_ICMP        0x00200000
#define WEB_SYN         0x00400000
#define WEB_ACK         0x00800000
#define LISTEN_ICMP     0x01000000
#define LISTEN_TCP      0x02000000
#define LISTEN_TCP_CON  0x04000000
#define LISTEN_UDP      0x08000000
#define LISTEN_ARP      0x10000000

#if defined(bool)
   #undef bool
#endif

#if defined(getch)
   #undef getch
#endif

#define hardtrue( a )   __builtin_expect(!!(a), true)
#define hardfalse( a )  __builtin_expect(!!(a), false)
#define __cache( a )    __builtin_prefetch(a)

#define __constructor__ __attribute__((constructor))
#define __destructor__  __attribute__((destructor))
#define __used__        __attribute__((used))
#define __unused__      __attribute__((unused))
#define __nocommon__    __attribute__((nocommon))
#define __obsolet__     __attribute__((deprecated))
#define __noreturn__    __attribute__((noreturn))
#define __packed__      __attribute__((packed))
#define __pure__        __attribute__((pure))
#define __malloc__      __attribute__((malloc))
#define __call__        __attribute__((const,used))

#undef show 
#undef log 
#undef pass
#define show(...)       fprintf(stdout, __VA_ARGS__)
#define log(...)        fprintf(stderr, __VA_ARGS__)
#define pass            __asm__ volatile("nop")
#define __LOOPBACK      "127.0.0.1"

#define compare(x,y) !strcmp(x,y) ? true : false
#if defined(_quit)
    #undef _quit
#endif
#define _quit( msg )     exit(log("%s (Core traceback: Line %d)\n\n", msg, __LINE__))
#define _assert( expr )  (expr) ? true : _quit("Assertion Error")

#if defined(__PACKET__)
   #undef __PACKET__
#endif

struct eth_addr {
   uint8 octet[6];
} __packed__;
#define ethaddr          struct eth_addr

typedef int bool;
time_t _time;
struct tm *_t;
signed int __sockets[SLIMIT];
char addressbuff[sizeof(struct sockaddr_in) * 2];
uint32 __pool;
pcap_t *__session;

struct __return {
    bool success;
    char errmsg[512];
} ret;

struct __data {
   struct sockaddr_in *source;
   struct sockaddr_in *target;
} __packed__;

#define __PACKET__
struct __input__ {
   uint16 port;             /* TCP/UDP port              */
   uint16 srcport;          /* TCP/UDP source port       */
   uint32 icmpType;         /* ICMP packet type          */
   uint32 tcpType;          /* TCP packet type           */
   uint32 webType;          /* WEB Stress packet type    */
   uint32 ircType;          /* IRC type option           */
   uint8 packetDisplay:1;   /* Show packet content       */
   char macsrc[ETH_LEN];    /* Source Mac addres         */
   char macdst[ETH_LEN];    /* Destination Mac address   */
   char interface[16];      /* Interface name            */
   signed int bpf;          /* BSD bpf device            */
   char ircRoom[64];        /* IRC room name             */

} __packed__ *pkt;


/* Exported global symbols */
void __initing( void ) __constructor__;
void __exiting( void ) __destructor__;

void            __sigcatch(int);
const char      *eth_ntoa(struct eth_addr *);
struct eth_addr *eth_aton_r(const char *, struct eth_addr *);
void            __born(void);
void            __cleaning(void );
signed int      __socketPool(const bool, const uint8, const bool);
uint16          __checksum(uint16 *, const uint32);
void            __set_broadcast(const uint32);
void            __set_nodelay(const uint32);
void            __set_hdrincl(const uint32);
void            __set_nonblock(const uint32);
bool            __lookup(struct sockaddr_in *,char *,const uint16,const bool);
void            __sysdate(void);
unsigned        __getch(void);
uint32          __randomIp(void);
const char     *__randomMac(void);
int             __fetchIp(const char *, char *);
const char     *__fetchMac(const char *);
bool            __checkBPF(const char *);
void            __show_packet(const uchar *, const uint16);
const char     *__getmonth(const char *);


#endif /* MPTCP_CORE_H */