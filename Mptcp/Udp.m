//
//  Udp.m
//  Mptcptmp
//
//  Created by Felipe Ecker on 02/07/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import "Udp.h"

static struct __data _data;   /* Sender bulk */

@implementation Udp

- (id) init {
    self = [super init];
    
    if (self) self.threads = [NSMutableArray arrayWithCapacity:50];
    return self;
}


- (void) ReturnKeyboard {
    [self.target resignFirstResponder];
    [self.source resignFirstResponder];
    [self.port resignFirstResponder];
    [self.srcPort resignFirstResponder];
}


- (void)editChanged {
    if ( self.listen.on && (self.srcPort.text.length > 0) ) {
        self.start.enabled = YES;
        return;
    }
    
    if ((self.target.text.length < 2) || self.port.text.length < 1) {
        self.start.enabled = NO;
        return;
    }
    self.start.enabled = YES;
}


- (void) changeTtl {
    NSString *str = [[NSString alloc] initWithFormat:@"%.0f", self.ttlSlider.value];
    self.ttl.text = str;
}


- (void) changeCount {
    NSString *str = [[NSString alloc] initWithFormat:@"%.0f", self.countSlider.value];
    self.count.text = str;
}


- (void) changeSize {
    NSString *str = [[NSString alloc] initWithFormat:@"%d", ((int) self.sizeSlider.value * 2)];
    self.size.text = str;
}


- (void) changeThreads {
    NSString *str = [[NSString alloc] initWithFormat:@"%.0f", self.threadsSlider.value];
    self.threadsLabel.text = str;
}


- (void) changeStates {
    
    if (self.listen.on) {
        self.target.enabled = NO;
        [self.target setAlpha:.6];
        self.port.enabled = NO;
        [self.port setAlpha:.6];
        self.source.enabled = NO;
        [self.source setAlpha:.6];
        self.again.enabled = NO;
        self.flood.enabled = NO;
        self.ttlSlider.enabled = NO;
        self.sizeSlider.enabled = NO;
        self.countSlider.enabled = NO;
        self.threadsSlider.enabled = NO;
        self.packetDisplay.enabled = YES;
        if (self.srcPort.text.length > 0) self.start.enabled = YES;
    } else {
        self.target.enabled = YES;
        [self.target setAlpha:1];
        self.port.enabled = YES;
        [self.port setAlpha:1];
        self.source.enabled = YES;
        [self.source setAlpha:1];
        self.again.enabled = YES;
        self.flood.enabled = YES;
        self.ttlSlider.enabled = YES;
        self.sizeSlider.enabled = YES;
        self.countSlider.enabled = YES;
        self.threadsSlider.enabled = YES;
        self.packetDisplay.enabled = NO;
        if (self.target.text.length < 2 || self.port.text.length < 1) self.start.enabled = NO;
        else self.start.enabled = YES;
    }
    
    if (self.flood.on) {
        self.again.enabled = NO;
        self.listen.enabled = NO;
        self.countSlider.enabled = NO;
    } else {
        if (!self.listen.on) self.again.enabled = YES;
        self.listen.enabled = YES;
        if (!self.listen.on) self.countSlider.enabled = YES;
    }
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


static void __bsd_listen ( uchar *args,
                          const struct pcap_pkthdr *hdr,
                          const uchar *recvbuff )
{
    
    auto struct ip *ip      = (struct ip *) (recvbuff + SIZE_ETH);
    auto struct udphdr *udp = (struct udphdr *) (recvbuff + SIZE_IP+ SIZE_ETH);
    
    __sysdate();
    auto char aux[256], address[INET_ADDRSTRLEN];
    
    if (ip->ip_p != IPPROTO_UDP) return;
    if ( ntohs(udp->uh_dport) != pkt->srcport ) return;
    
    memset(aux, 0, sizeof(aux));
    inet_ntop(AF_INET, &(ip->ip_src), address, INET_ADDRSTRLEN);
    snprintf(aux, sizeof(aux) -1 , "(%02d:%02d:%02d) Received UDP packet from host [%s]", _t->tm_hour, _t->tm_min, _t->tm_sec, address);

    
    [Console roll:[NSString stringWithFormat:@"%s", aux] forInit:false toTittle:false inDump:false];
    [CATransaction flush];
    
    if (pkt->packetDisplay) __show_packet(&recvbuff[14], ntohs(ip->ip_len));
    [CATransaction flush];
    
    return;
}


- (void) __doListen {
    
    [Console __roll:[NSString stringWithFormat:@"Listening for UDP data on local port (%d):", [self.srcPort.text intValue]] forInit:false toTittle:true inDump:true];
    [self __print:@""];
    
    char *eth, err_buff[PCAP_ERRBUF_SIZE];
    
    if ( !(eth = pcap_lookupdev(err_buff)) ) {
        snprintf(ret.errmsg, 511, "On grab system's interface device. Detail: %s", err_buff);
        ret.success = false;
        return;
    }
    
    if ( !(__session = pcap_open_live(eth, [self.size.text intValue] + 128, true, 1, err_buff)) ) {
        snprintf(ret.errmsg, 511, "Couldn't open interface device %s to listen packets. Detail: %s", eth, err_buff);
        ret.success = false;
        return;
    }
    
    pcap_loop(__session, -1, __bsd_listen, NULL);
    return;
}


- (void) __packing:(uchar *) __buffer withSize:(uint16) __size
                            atSource:(const struct sockaddr_in *) __source
                            atTarget:(const struct sockaddr_in *) __target {
    

    struct ip *__ip = (struct ip *) __buffer;
    
    struct udphdr *__udp = (struct udphdr *) (__buffer + SIZE_IP);
    struct __auxhdr {
        uint32 saddr;
        uint32 daddr;
        uint8 useless;
        uint8 proto;
        uint16 udpsiz;
        struct udphdr udp;
        uchar data[1];
        
    };

    struct __auxhdr *udpaux = (struct __auxhdr *) calloc(1, sizeof(struct __auxhdr) + (__size - 1));
    
    __ip->ip_src   = __source->sin_addr;
    __ip->ip_dst   = __target->sin_addr;
    __ip->ip_v     = 0x04;
    __ip->ip_hl    = 0x05;
    __ip->ip_ttl   = [self.ttl.text intValue];
    __ip->ip_id    = htons(rand() % 0xFFFF);
    __ip->ip_p     = IPPROTO_UDP;
    __ip->ip_len   = __size; /* HeaderIP and headerUDP: 28 bytes */
    __ip->ip_sum   = __checksum((uint16 *) __ip, SIZE_IP);
    
    __udp->uh_sport= __source->sin_port;
    __udp->uh_dport= __target->sin_port;
    __udp->uh_ulen = htons(__size - SIZE_IP);
    __udp->uh_sum  = 0x00;
    
    //memset(&udpaux, 0, sizeof(struct __auxddhdr));
    udpaux->saddr   = __ip->ip_src.s_addr;
    udpaux->daddr   = __ip->ip_dst.s_addr;
    udpaux->useless = 0x0;
    udpaux->proto   = IPPROTO_UDP;
    udpaux->udpsiz  = htons(__size - SIZE_IP);
    
    memcpy(&(udpaux->udp), __udp, SIZE_UDP);
    __udp->uh_sum  = __checksum( (uint16 *) udpaux, (__size - SIZE_IP));
    
    free(udpaux);
    return;
}


- (void) __send:(NSNumber *) index {
        
    signed int sock;
    if ( !( sock = __socketPool(true, 0, false)) ) return;
    __set_hdrincl(sock);
    
    uchar cbuffer[[self.size.text intValue] + 40] __nocommon__;
    memset(cbuffer, 0, sizeof(cbuffer));
    [self __packing:cbuffer withSize:(uint16)sizeof(cbuffer) atSource:_data.source atTarget:_data.target];
    
    uint32 count = [self.count.text intValue];
    unsigned _sizeof = sizeof(struct sockaddr_in);
    
    auto char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);
    
    do {

        [self __print:[NSString stringWithFormat:@"(%d) Sending UDP packet to [%s] on port %d", self->__count++, address, [self.port.text intValue]]];
        
        if ( hardfalse(sendto(sock, cbuffer, sizeof(cbuffer), 0, (struct sockaddr *) _data.target, _sizeof) < 0) ) {
            snprintf(ret.errmsg, 511, "On send UDP packets. Restart the Mptcp.");
            ret.success = false;
            return;
        }
        
        if (self.stop) break;
        if ([self.count.text intValue]) {
            --(count);
            if (!count) break;
        }
        
        [self __packing:cbuffer withSize:(uint16)sizeof(cbuffer) atSource:_data.source atTarget:_data.target];
        
        [CATransaction flush];
        [NSThread sleepForTimeInterval:1.0];
        
    } while (self.again.on || count);
    
    return;
}


- (void) __burst:(NSNumber *) index {
    register signed int sock;
 
    // RAW socket
    if ( !( sock = __socketPool(true, 0, false)) ) return;
    __set_hdrincl(sock);
    
    uchar cbuffer[[self.size.text intValue] + 40] __nocommon__;
    memset(cbuffer, 0, sizeof(cbuffer));
    [self __packing:cbuffer withSize:(uint16)sizeof(cbuffer) atSource:_data.source atTarget:_data.target];
    
    auto char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);
    
    [self __print:[NSString stringWithFormat:@"[BURST] Sending UDP packets to [%s] on port %d..", address, [self.port.text intValue]]];
    
    register uint8 tsize = sizeof(struct sockaddr_in);
    register uint32 size = sizeof(cbuffer);
    register uchar *buffer = cbuffer;
    register struct sockaddr_in *targ = _data.target;
    
    do {
        if ( hardfalse(sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize) < 0)) {
            snprintf(ret.errmsg, 511, "On send TCP packets. Restart the Mptcp.");
            ret.success = false;
            return;
        }
        [self __packing:cbuffer withSize:(uint16)sizeof(cbuffer) atSource:_data.source atTarget:_data.target];
    } while (!self.stop);
    
    return;
}


- (void) run {
    self.check = [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(__check_return) userInfo:nil repeats:YES];
    
    memset(pkt, 0, sizeof(struct __input__));

    pkt->port = [self.port.text intValue];
    pkt->srcport = [self.srcPort.text intValue];
    ret.success = true;
    self.stop = NO;
    [self.threads removeAllObjects];
    self->__count = 0;
    pkt->packetDisplay = (self.packetDisplay.on) ? 1 : 0;
    
    const char *month = __getmonth("__today__");
    [Console __roll:[NSString stringWithFormat:@"               Starting MpTcp %s at [%02d.%s.%02d %02d:%02d:%02d]", VERSION, _t->tm_mday, month, _t->tm_year+1900, _t->tm_hour, _t->tm_min, _t->tm_sec] forInit:true toTittle:true inDump:false];
    [Console __roll:@"                       Mptcp Project <www.hexcodes.org>" forInit:false toTittle:true inDump:false];
    [self __print:@""];

    if ((self.port.text.length > 5) ||
        (self.srcPort.text.length > 5) ||
        ((self.port.text.length > 0) && ([self.port.text intValue] < 1)) ||
        ((self.port.text.length > 0) && ([self.port.text intValue] > 65535)) ||
        ((self.srcPort.text.length > 0) && ([self.srcPort.text intValue] < 1)) ||
        ((self.srcPort.text.length > 0) && ([self.srcPort.text intValue] > 65535))
        ) {
        snprintf(ret.errmsg, 511, "Invalid port number.");
        ret.success = false;
        return;
    }
    
    _data.source = (struct sockaddr_in *) addressbuff;
    _data.target = (struct sockaddr_in *) (addressbuff + sizeof(struct sockaddr_in));

    if (self.listen.on) {
        NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__doListen) object:nil];
        [thread start];
        return;
    }
    
    if (!__lookup(_data.source, (char *)[self.source.text UTF8String], [self.srcPort.text intValue], true)) return;
    if (!__lookup(_data.target, (char *)[self.target.text UTF8String], [self.port.text intValue], false)) return;
    
    //Pool of threads...
    for (uint index = 0; index < [self.threadsLabel.text intValue]; index++ ) {
        if (self.flood.on) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__burst:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        } else {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__send:) object:[NSNumber numberWithUnsignedInt:index]];
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
