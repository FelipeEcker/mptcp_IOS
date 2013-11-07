//
//  Icmp.m
//  Mptcp
//
//  Created by Felipe Ecker on 14/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import "Icmp.h"

static struct __data _data;   /* Sender bulk */
const char *tags[] = {
    "ICMP (Echo Request)",
    "ICMP (Echo Reply)",
    "ICMP (Source Quench)",
    "ICMP (Mask Request)",
    "ICMP (Mask Reply)",
    "ICMP (Info Request)",
    "ICMP (Time Request)",
    "ICMP (Time Reply)",
    "ICMP (Info Reply)",
    "Unknown ICMP data"
};

#define __tagging( __tag,type ) do {                                \
if ((type == 0x08) || (type & ICMP_ECHO_REQ)) pass;              \
else if ((type == 0x00) || (type & ICMP_ECHO_REPLY)) __tag++;    \
else if ((type == 0x04) || (type & ICMP_SRC_QUENCH)) __tag += 2; \
else if ((type == 0x11) || (type & ICMP_MASK_REQ)) __tag += 3;   \
else if ((type == 0x12) || (type & ICMP_MASK_REPLY)) __tag += 4; \
else if ((type == 0x0F) || (type & ICMP_INFO)) __tag += 5;       \
else if ((type == 0x0D) || (type & ICMP_TIME_REQ)) __tag += 6;   \
else if (type == 0x0E) __tag += 7;                               \
else if (type == 0x10) __tag += 8;                               \
else __tag += 9;                                                 \
} while(0)


@implementation Icmp

- (id) init {
    self = [super init];

    if (self) {
        self.types = @[
                    @"Echo Req. (Ping)",
                    @"Echo Reply",
                    @"Information Req.",
                    @"Time Request",
                    @"Source Quench",
                    @"Mask Request"];
        
        self.pickerNumberComponents = 1;
        self.pickerNumberRows = [self.types count];
        
        self.threads = [NSMutableArray arrayWithCapacity:50];
    }
    return self;
}


- (void) ReturnKeyboard {
    [self.target resignFirstResponder];
    [self.source resignFirstResponder];
}


- (void)editChanged {
    if (self.target.text.length < 2) self.start.enabled = NO;
    else self.start.enabled = YES;
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
        self.source.enabled = NO;
        [self.source setAlpha:.6];
        [self.picker setUserInteractionEnabled:NO];
        [self.picker setAlpha:.6];
        self.again.enabled = NO;
        self.flood.enabled = NO;
        self.noReplies.enabled = NO;
        self.ttlSlider.enabled = NO;
        self.sizeSlider.enabled = NO;
        self.countSlider.enabled = NO;
        self.threadsSlider.enabled = NO;
        self.start.enabled = YES;
    } else {
        self.target.enabled = YES;
        [self.target setAlpha:1];
        self.source.enabled = YES;
        [self.source setAlpha:1];
        [self.picker setUserInteractionEnabled:YES];
        [self.picker setAlpha:1];
        self.again.enabled = YES;
        self.flood.enabled = YES;
        self.noReplies.enabled = YES;
        self.ttlSlider.enabled = YES;
        self.sizeSlider.enabled = YES;
        self.countSlider.enabled = YES;
        self.threadsSlider.enabled = YES;
        if (self.target.text.length < 2) self.start.enabled = NO;
        else self.start.enabled = YES;
    }
    
    if (self.flood.on) {
        self.again.enabled = NO;
        self.listen.enabled = NO;
        self.noReplies.enabled = NO;
        self.countSlider.enabled = NO;
        self.packetDisplay.enabled = NO;
    } else {
        if (!self.listen.on) self.again.enabled = YES;
        self.listen.enabled = YES;
        self.noReplies.enabled = YES;
        if (!self.listen.on) self.countSlider.enabled = YES;
        self.packetDisplay.enabled = YES;
    }
    
    if (self.packetDisplay.on) {
        self.noReplies.enabled = NO;
    }
    else {
        if(self.listen.on || self.flood.on) self.noReplies.enabled = NO;
        else self.noReplies.enabled = YES;
    }
    
    if (self.noReplies.on) {
        self.packetDisplay.enabled = NO;
    }
    else {
        if (self.flood.on) self.packetDisplay.enabled = NO;
        else self.packetDisplay.enabled = YES;
    }
}


- (NSString *) pickerTitle:(NSInteger)row {
    return self.types[row];
}


- (void) pickerSelectedRow:(NSInteger)row {
    self.type.text = self.types[row];
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


static void __bsd_listen (   uchar *args,
                          const struct pcap_pkthdr *hdr,
                          const uchar *recvbuff )
{
    
    /* auto struct ether_header *h = (struct ether_header *) recvbuff; */
    auto struct ip *ip        = (struct ip *) (recvbuff + SIZE_ETH);
    auto struct icmp *icmp    = (struct icmp *) (recvbuff + SIZE_IP + SIZE_ETH);
    auto struct in_addr *mask = (struct in_addr *) (recvbuff + SIZE_ICMP + SIZE_IP + SIZE_ETH);
    
    const char **tag;
    tag = tags;
    __tagging(tag, (uint32) icmp->icmp_type);
    __sysdate();
    
    auto char aux[20] __nocommon__, address[INET_ADDRSTRLEN] __nocommon__;
    
    if (ip->ip_p == IPPROTO_ICMP) {
        
        memset(aux, 0, sizeof(aux));
        if (icmp->icmp_type == 0x12) {
            inet_ntop(AF_INET, &(*mask), address, INET_ADDRSTRLEN);
            snprintf(aux, sizeof(aux)-1," [%s]", address);
        }
        
        inet_ntop(AF_INET, &(ip->ip_src), address, INET_ADDRSTRLEN);
        [Console roll:[NSString stringWithFormat:@"(%02d:%02d:%02d) Received %s%s from (%s)", _t->tm_hour, _t->tm_min, _t->tm_sec, *tag, aux, address] forInit:false toTittle:false inDump:false];
        
        recvbuff += 14;
        if (pkt->packetDisplay) __show_packet(recvbuff, ntohs(ip->ip_len));
        [CATransaction flush];
    }
    
    return;
}


- (void) __doListen {
    
    [Console __roll:@"Listening for ICMP data:" forInit:false toTittle:true inDump:true];
    [self __print:@""];
    
    char *eth, err_buff[PCAP_ERRBUF_SIZE];
    
    if ( !(eth = pcap_lookupdev(err_buff)) ) {
        snprintf(ret.errmsg, 511, "On grab system's interface. Detail: %s", err_buff);
        ret.success = false;
        return;
    }

    if ( !(__session = pcap_open_live(eth, [self.size.text intValue] + 512, true, 1, err_buff)) ) {
        snprintf(ret.errmsg, 511, "Couldn't open device %s. Detail: %s", eth, err_buff);
        ret.success = false;
        return;
    }

    pcap_loop(__session, -1, __bsd_listen, NULL);
}

- (void) __doResponse: (int) sock {
    
    uchar recvbuff[[self.size.text intValue] + 40];
    memset(recvbuff, 0, sizeof(recvbuff));

    char address[INET_ADDRSTRLEN];
    unsigned _sizeof = sizeof(struct sockaddr_in);
    register struct ip *recvip = (struct ip *) recvbuff;
    struct sockaddr_in remote;
    struct timeval _times;
    fd_set beep;
    
    _times.tv_sec = 4;
    _times.tv_usec = 0;
    FD_ZERO(&beep);
    FD_SET(sock, &beep);
    
    do {
        if (
            !select(sock+1, &beep, NULL, NULL, &_times) ) {
            snprintf(ret.errmsg, 511, "Timeout");
            ret.success = false;
            return;
        }
        if ( hardfalse(recvfrom(sock, recvbuff, sizeof(recvbuff), 0, \
                                (struct sockaddr *) &remote, &_sizeof) < 0) ) {
            snprintf(ret.errmsg, 511, "On received data.");
            ret.success = false;
            return;
        }
    } while (_data.target->sin_addr.s_addr != remote.sin_addr.s_addr);
    
    inet_ntop(AF_INET, &(recvip->ip_src), address, INET_ADDRSTRLEN);
    if (pkt->icmpType & ICMP_ECHO_REQ) [self __print:[NSString stringWithFormat:@"   --> Received ICMP Echo Reply from [%s]", address]];
    else if (pkt->icmpType & ICMP_MASK_REQ) [self __print:[NSString stringWithFormat:@"   --> Received ICMP Mask Reply from [%s]", address]];
    else if (pkt->icmpType & ICMP_TIME_REQ) [self __print:[NSString stringWithFormat:@"   --> Received ICMP Timestamp Reply from [%s]", address]];
    if (!self.packetDisplay.on) [self __print:@" "];
    
    if (self.packetDisplay.on) __show_packet(recvbuff, (recvip->ip_len + SIZE_IP));
}


- (void) __packing:(const uchar *) __buffer withSize:(const uint32) __size {
    
    struct ip *__ip = (struct ip *) __buffer;
    struct icmp *__icmp = (struct icmp *) (__buffer + SIZE_IP);
    
    __ip->ip_src   = _data.source->sin_addr;
    __ip->ip_dst   = _data.target->sin_addr;
    __ip->ip_id    = htons(rand() % 0XFFFF);
    __ip->ip_v     = 0x04;
    __ip->ip_hl    = 0x05;
    __ip->ip_ttl   = [self.ttl.text intValue];
    __ip->ip_p     = IPPROTO_ICMP;
    __ip->ip_len   = __size; // HeaderIP and headerICMP: 28 bytes
    __ip->ip_sum   = __checksum((uint16 *) __ip, SIZE_IP);
    
    if (pkt->icmpType & ICMP_ECHO_REQ)         __icmp->icmp_type = 0x08;
    else if (pkt->icmpType & ICMP_ECHO_REPLY)  __icmp->icmp_type = 0x00;
    else if (pkt->icmpType & ICMP_INFO)        __icmp->icmp_type = 0x0F;
    else if (pkt->icmpType & ICMP_TIME_REQ)    __icmp->icmp_type = 0x0D;
    else if (pkt->icmpType & ICMP_SRC_QUENCH)  __icmp->icmp_type = 0x04;
    else if (pkt->icmpType & ICMP_MASK_REQ)    __icmp->icmp_type = 0x11;
    
    __icmp->icmp_code  = 0x00;
    __icmp->icmp_id    = htons(rand() % 0xFFFF);
    __icmp->icmp_seq   = htons(rand() % 0xFFFF);
    
    __icmp->icmp_cksum = __checksum( (uint16 *) __icmp, SIZE_ICMP);
}


- (void) __burst:(NSNumber *) index {
    
    register signed int sock;
    
    // ICMP RAW socket
    if ( !( sock = __socketPool(false, __ICMP_MODE__, false)) ) return;
    
    __set_broadcast(sock);
    __set_hdrincl(sock);
    
    register uchar cbuffer[[self.size.text intValue] + 40];
    register uint bufferSize = sizeof(cbuffer);
    
    memset(cbuffer, 0, sizeof(cbuffer));
    [self __packing:cbuffer withSize:(uint32) sizeof(cbuffer)];
    
    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);
    register uint targetSize = sizeof(struct sockaddr_in);
    
    const char **tag = tags;
    __tagging(tag, pkt->icmpType);

    [self __print:[NSString stringWithFormat:@"[BURST] Sending %s to [%s]", *tag, address]];
    [CATransaction flush];
    
    do {
        if ( hardfalse(sendto(sock, cbuffer, bufferSize, 0, (struct sockaddr *) _data.target, targetSize) < 0) ) {
            snprintf(ret.errmsg, 511, "On send ICMP packets. Restart the Mptcp.");
            ret.success = false;
        }
    } while (!self.stop);
    
    return;
}


- (void) __send:(NSNumber *) index {
    
    register signed int sock;
    if ( !( sock = __socketPool(false, __ICMP_MODE__, false)) ) return;
    
    __set_broadcast(sock);
    __set_hdrincl(sock);
    
    const char **tag = tags;
    __tagging(tag, pkt->icmpType);
    
    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);
    
    uchar cbuffer[[self.size.text intValue] + 40];
    memset(cbuffer, 0, sizeof(cbuffer));
    [self __packing:cbuffer withSize:(uint32) sizeof(cbuffer)];
 
    register uint __count__ = [self.count.text intValue];
    
    do {
        [self __print:[NSString stringWithFormat:@"[%d] Sending %s to (%s)", self->__count++, *tag, address]];
        if ( hardfalse(sendto(sock, cbuffer, sizeof(cbuffer), 0, (struct sockaddr *) _data.target, sizeof(struct sockaddr_in)) < 0) ) {
            snprintf(ret.errmsg, 511, "On send ICMP packets. Restart the Mptcp.");
            ret.success = false;
            return;
        }
        
        if ( hardtrue( (!self.noReplies.on) && ((pkt->icmpType & ICMP_ECHO_REQ) || (pkt->icmpType & ICMP_MASK_REQ) || (pkt->icmpType & ICMP_TIME_REQ))) )
            [self __doResponse:sock];

        if (self.stop) break;
        if ([self.count.text intValue]) {
            --(__count__);
            if (!__count__) break;
        }
        
        [CATransaction flush];
        [NSThread sleepForTimeInterval:1.0];

    } while (self.again.on || __count__);
    return;
}


- (void) run {
    self.check = [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(__check_return) userInfo:nil repeats:YES];
    
    memset(pkt, 0, sizeof(struct __input__));

    if ([self.type.text isEqual:@"Echo Req. (Ping)"]) pkt->icmpType = ICMP_ECHO_REQ;
    else if ([self.type.text isEqualToString:@"Information Req."]) pkt->icmpType = ICMP_INFO;
    else if ([self.type.text isEqualToString:@"Time Request"]) pkt->icmpType = ICMP_TIME_REQ;
    else if ([self.type.text isEqualToString:@"Echo Reply"]) pkt->icmpType = ICMP_ECHO_REPLY;
    else if ([self.type.text isEqualToString:@"Mask Request"])  pkt->icmpType = ICMP_MASK_REQ;
    else if ([self.type.text isEqualToString:@"Source Quench"]) pkt->icmpType = ICMP_SRC_QUENCH;
    else pkt->icmpType = ICMP_ECHO_REQ;
    
    ret.success = true;
    self.stop = NO;
    [self.threads removeAllObjects];
    self->__count = 0;
    pkt->packetDisplay = (self.packetDisplay.on) ? 1 : 0;
    
    const char *month = __getmonth("__today__");
    [Console __roll:[NSString stringWithFormat:@"               Starting MpTcp %s at [%02d.%s.%02d %02d:%02d:%02d]", VERSION, _t->tm_mday, month, _t->tm_year+1900, _t->tm_hour, _t->tm_min, _t->tm_sec] forInit:true toTittle:true inDump:false];
    [Console __roll:@"                       Mptcp Project <www.hexcodes.org>" forInit:false toTittle:true inDump:false];
    [self __print:@""];
    
    
    if (self.listen.on) {
        NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__doListen) object:nil];
        [thread start];
        return;
    }
    
    _data.source = (struct sockaddr_in *) addressbuff;
    _data.target = (struct sockaddr_in *) (addressbuff + sizeof(struct sockaddr_in));
  
    if (!__lookup(_data.source, (char *)[self.source.text UTF8String], 0, true)) return;
    if (!__lookup(_data.target, (char *)[self.target.text UTF8String], 0, false)) return;
   
    //Pool of threads - Overture...
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
