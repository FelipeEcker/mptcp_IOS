//
//  Arp.m
//  Mptcptmp
//
//  Created by Felipe Ecker on 03/07/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import "Arp.h"

static struct __data _data;   /* Sender bulk */

@implementation Arp

- (id) init {
    self = [super init];
    
    if (self) {
        self.typesA = @[@"ARP",@"RARP"];
        self.typesB = @[@"Reply",@"Request"];
        
        self.pickerNumberComponents = 2;
        self.pickerNumberRows = [self.typesA count];
        
        self.threads = [NSMutableArray arrayWithCapacity:50];
    }
    return self;
}


- (void) ReturnKeyboard {
    [self.target resignFirstResponder];
    [self.source resignFirstResponder];
    [self.macdst resignFirstResponder];
    [self.macsrc resignFirstResponder];
    [self.targetArping resignFirstResponder];
    [self.targetMacflood resignFirstResponder];
    [self.targetArpcannon1 resignFirstResponder];
    [self.targetArpcannon2 resignFirstResponder];
    [self.targetException resignFirstResponder];
}


-(void)editChanged {

    if ( (!self.listen.on) && (self.macdst.text.length < 2)) self.start.enabled = NO;
    else self.start.enabled = YES;

    if (self.targetArping.text.length > 2 && !self.listen.on) self.startArping.enabled = YES;
    else self.startArping.enabled = NO;

    if (self.targetMacflood.text.length > 0 && !self.listen.on) self.startMacflood.enabled = YES;
    else self.startMacflood.enabled = NO;
    
    if ((self.targetArpcannon1.text.length > 2) && (self.targetArpcannon2.text.length > 2) && !self.listen.on) self.startArpcannon.enabled = YES;
    else self.startArpcannon.enabled = NO;
}


- (void) changeThreads {
    NSString *str = [[NSString alloc] initWithFormat:@"%.0f", self.threadsSlider.value];
    self.threadsLabel.text = str;
}


- (void) changeThreadsArping {
    NSString *str = [[NSString alloc] initWithFormat:@"%.0f", self.threadsSliderArping.value];
    self.threadsArping.text = str;
}


- (void) changeThreadsMacflood {
    NSString *str = [[NSString alloc] initWithFormat:@"%.0f", self.threadsSliderMacflood.value];
    self.threadsMacflood.text = str;
}


- (void) changeThreadsArpcannon {
    NSString *str = [[NSString alloc] initWithFormat:@"%.0f", self.threadsSliderArpcannon.value];
    self.threadsArpcannon.text = str;
}


- (void) changeStates {
    if (self.listen.on) {
        self.target.enabled = NO;
        [self.target setAlpha:.6];
        self.source.enabled = NO;
        [self.source setAlpha:.6];
        self.macdst.enabled = NO;
        [self.macdst setAlpha:.6];
        self.macsrc.enabled = NO;
        [self.macsrc setAlpha:.6];
        [self.picker setUserInteractionEnabled:NO];
        [self.picker setAlpha:.6];
        self.again.enabled = NO;
        self.flood.enabled = NO;
        self.threadsSlider.enabled = NO;
        self.broadcast.enabled = NO;
        [self.broadcast setAlpha:.6];
        self.packetDisplay.enabled = YES;
        self.start.enabled = YES;
    } else {
        self.target.enabled = YES;
        [self.target setAlpha:1];
        self.source.enabled = YES;
        [self.source setAlpha:1];
        self.macdst.enabled = YES;
        [self.macdst setAlpha:1];
        self.macsrc.enabled = YES;
        [self.macsrc setAlpha:1];
        [self.picker setUserInteractionEnabled:YES];
        [self.picker setAlpha:1];
        self.again.enabled = YES;
        self.flood.enabled = YES;
        self.broadcast.enabled = YES;
        [self.broadcast setAlpha:1];
        self.threadsSlider.enabled = YES;
        self.packetDisplay.enabled = NO;
        if (self.macdst.text.length < 2) self.start.enabled = NO;
        else self.start.enabled = YES;
    }
    
    if (self.flood.on) {
        self.again.enabled = NO;
        self.listen.enabled = NO;
    } else {
        if (!self.listen.on) self.again.enabled = YES;
        self.listen.enabled = YES;
    }
    
    return;
}


- (NSString *) pickerTitle:(NSInteger)row inComponent:(NSInteger)component {
    if (component == 0) return self.typesA[row];
    
    return self.typesB[row];
}


- (void) pickerSelectedRow:(NSInteger)row inComponent:(NSInteger)component {
    if (component == 0) self.typeA.text = self.typesA[row];
    else self.typeB.text = self.typesB[row];
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


- (void) setBroadcast {
    self.macdst.text = @"FF:FF:FF:FF:FF:FF";
    self.start.enabled = YES;
}


static void __bsd_listen (  u_char *args,
                          const struct pcap_pkthdr *hdr,
                          const u_char *recvbuff )
{
    struct __ethdr *ether = (struct __ethdr *) recvbuff;
    auto char address_src[INET_ADDRSTRLEN], address_dst[INET_ADDRSTRLEN];
    
    __sysdate();
    inet_ntop(AF_INET, &(ether->ipsrc), address_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ether->ipdst), address_dst, INET_ADDRSTRLEN);
    
    if ( htons(ether->proto) == (uint16) ETH_ARP ) {
        if ( htons(ether->type) == (uint16) ETH_ARPREQ ) {
            [Console roll:[NSString stringWithFormat:@"Received ARP REQUEST from %s (%s) asking who is [%s]", address_src, eth_ntoa(&ether->macsrc), address_dst] forInit:false toTittle:false inDump:false];
        } else if ( htons(ether->type) == (uint16) ETH_ARPREPLY ) {
            [Console roll:[NSString stringWithFormat:@"Received ARP REPLY packet from (%s) saying it is [%s]", address_src, eth_ntoa(&ether->macsrc)] forInit:false toTittle:false inDump:false];
        } else {
            [Console roll:@"Received an unknown ARP packet type." forInit:false toTittle:false inDump:false];
        }
        
    } else if ( htons(ether->proto) == (uint16) ETH_RARP ) {
        if ( htons(ether->type) == (uint16) ETH_RARPREQ ) {
            [Console roll:[NSString stringWithFormat:@"Received RARP REQUEST from %s (%s) asking who is [%s]", address_src, eth_ntoa(&ether->macsrc), eth_ntoa(&ether->macdst)] forInit:false toTittle:false inDump:false];
        } else if ( htons(ether->type) == (uint16) ETH_RARPREPLY ) {
            [Console roll:[NSString stringWithFormat:@"Received RARP REPLY from (%s) saying your IP is [%s]", eth_ntoa(&ether->macsrc), address_src] forInit:false toTittle:false inDump:false];
        } else {
            [Console roll:@"Received an unknown RARP packet type." forInit:false toTittle:false inDump:false];
        }
        
    } else return;
    
    if (pkt->packetDisplay) __show_packet(recvbuff, 42);
    [Console roll:@"" forInit:false toTittle:false inDump:false];
    [CATransaction flush];
    
    return;
}


- (void) __doListen {
    
    [Console __roll:@"Listening for ARP/RARP data:" forInit:false toTittle:true inDump:true];
    [self __print:@""];
    
    char *eth, err_buff[PCAP_ERRBUF_SIZE];
    
    if ( !(eth = pcap_lookupdev(err_buff)) ) {
        snprintf(ret.errmsg, 511, "On grab system's interface device. Detail: %s", err_buff);
        ret.success = false;
        return;
    }
    
    if ( !(__session = pcap_open_live(eth, 42, true, 1, err_buff)) ) {
        snprintf(ret.errmsg, 511, "Couldn't open interface device %s to listen packets. Detail: %s", eth, err_buff);
        ret.success = false;
        return;
    }
    
    pcap_loop(__session, -1, __bsd_listen, NULL);
    return;
}


- (void) __packing:(uchar *) __buffer
        withSource:(uint32) __source
        withTarget:(uint32) __target
        withMacsrc:(const char *) macsrc
        withMacdst:(const char *) macdst
        withType:(uint16) arpType
        withMode:(uint16) mode {

    struct __ethdr *__eth = (struct __ethdr *) __buffer;
    
    eth_aton_r(macsrc, &__eth->macsrc);
    eth_aton_r(macdst, &__eth->macdst);
    __eth->proto    = htons(arpType);
    __eth->unused0  = (uint16) htons(0x0001);
    __eth->unused1  = (uint16) htons(0x0800);
    __eth->unused2  = (uint16) htons(0x0604);
    
    /* 0x0001=ARP_REQUEST / 0x0002=ARP_REPLY /
     0x0003=RARP_REQUEST / 0x0004=RARP_REPLY
     */
    __eth->type     = htons(mode);
    __eth->ipsrc    = __source;
    __eth->ipdst    = __target;
    __eth->msrc     = __eth->macsrc;
    __eth->mdst     = __eth->macdst;
}


- (void) __send:(NSNumber *) index {

    const char *msg = ([self.typeA.text isEqualToString:@"ARP"]) ? "ARP" : "RARP";
    const uint16 type = ([self.typeA.text isEqualToString:@"ARP"]) ? ETH_ARP : ETH_RARP;
    uint16 mode;
    
    if (type == ETH_ARP) mode = ([self.typeB.text isEqualToString:@"Request"]) ? ETH_ARPREQ : ETH_ARPREPLY;
    else mode = ([self.typeB.text isEqualToString:@"Request"]) ? ETH_RARPREQ : ETH_RARPREPLY;
    
    uchar cbuffer[42];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    [self __packing:cbuffer withSource:_data.source->sin_addr.s_addr withTarget:_data.target->sin_addr.s_addr withMacsrc:pkt->macsrc withMacdst:pkt->macdst withType:type withMode:mode];
    
    do {
        [Console roll:[NSString stringWithFormat:@"(%d) Sending %s packet to MAC address [%s]", self->__count, msg, [self.macdst.text UTF8String]] forInit:false toTittle:false inDump:false];
        [CATransaction flush];
        
        if (write(pkt->bpf, cbuffer, (uint32) sizeof(cbuffer)) < 0 ) {
            snprintf(ret.errmsg, 511, "On send packet.");
            ret.success = false;
            return;
        }
        
        if (self.stop) break;
        if (self.again.on) [NSThread sleepForTimeInterval:1.0];
    } while (self.again.on);
}


- (void) __burst:(NSNumber *) index {
        
    const char *msg = ([self.typeA.text isEqualToString:@"ARP"]) ? "ARP" : "RARP";
    register uint16 type = ([self.typeA.text isEqualToString:@"ARP"]) ? ETH_ARP : ETH_RARP;
    register uint16 mode;
    
    if (type == ETH_ARP) mode = ([self.typeB.text isEqualToString:@"Request"]) ? ETH_ARPREQ : ETH_ARPREPLY;
    else mode = ([self.typeB.text isEqualToString:@"Request"]) ? ETH_RARPREQ : ETH_RARPREPLY;
    
    uchar cbuffer[42];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    [self __packing:cbuffer withSource:_data.source->sin_addr.s_addr withTarget:_data.target->sin_addr.s_addr withMacsrc:pkt->macsrc withMacdst:pkt->macdst withType:type withMode:mode];
    
    register uchar *buffer = cbuffer;
    register uint8 size = (uint32) sizeof(cbuffer);
    
    [Console roll:[NSString stringWithFormat:@"[BURST] Sending %s packet to MAC address [%s]", msg, [self.macdst.text UTF8String]] forInit:false toTittle:false inDump:false];
    [CATransaction flush];
    
    do {
        write(pkt->bpf, buffer, size);
    } while (!self.stop);
    
    return;
}


- (bool) __validation_mac:(char *)buffer withMac:(const char *) mac {
    if (sscanf(mac, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
        &buffer[0],&buffer[1],&buffer[2],&buffer[3],
        &buffer[4],&buffer[5],&buffer[6],&buffer[7],
        &buffer[8],&buffer[9],&buffer[10],&buffer[11],
        &buffer[12],&buffer[13],&buffer[14],&buffer[15] ) != 12) {

        snprintf(ret.errmsg, 511, "Invalid Mac Address.");
        ret.success = false;
        return false;
    }
    
    snprintf(buffer, ETH_LEN, "%s", mac);
    
    for (register uint8 it=0; it < 17; it++) {
        if (tolower(buffer[it]) > 'f') {
            snprintf(ret.errmsg, 511, "Invalid MAC address format: Characters invalid.");
            ret.success = false;
            return false;
        }
    }
    
    return true;
}


- (bool) __validation_ip:(const char *) ip {
    signed int __ip[4];
    if (sscanf(ip, "%d.%d.%d.%d", &__ip[0], &__ip[1], &__ip[2], &__ip[3]) != 4) {
        snprintf(ret.errmsg, 511, "Invalid IP Address.");
        ret.success = false;
        return false;
    }
    for (uint8 it = 0; it < 3; it++) {
        if ((__ip[it] > 255) || (__ip[it] < 0)) {
            snprintf(ret.errmsg, 511, "Invalid IP address format field.");
            ret.success = false;
            return false;
        }
    }
    return true;
}


- (bool) __validation_count:(int) value {
    
    if ( (value < 0) || (value > 100000000) ) {
        snprintf(ret.errmsg, 511, "Invalid number of packets.");
        ret.success = false;
        return false;
    }
    
    return true;
}

static NSTimer *timer;
static uint __counter = 0;
static bool __timeout = false;

- (void) __checkTimeout {
    
    if (__timeout) {
        snprintf(ret.errmsg, 511, "Timeout...");
        ret.success = false;
    }
    
    [timer invalidate];
    timer = nil;
    return;
}


static void __arping_listen ( uchar *args,
                             const struct pcap_pkthdr *hdr,
                             const u_char *recvbuff)
{
    
    struct __ethdr *ether = (struct __ethdr *) recvbuff;
    
    if (_data.target->sin_addr.s_addr == ether->ipsrc) {
        auto char address[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);
        
        [Console roll:[NSString stringWithFormat:@"(%d) Reply from host %s [%s]", __counter++, address, eth_ntoa(&ether->macsrc)] forInit:false toTittle:false inDump:false];
        [CATransaction flush];
        
        __timeout = false;
        if (pkt->packetDisplay) __show_packet(recvbuff, 42);
        pcap_breakloop(__session);
    }
}


- (void) __arping:(NSNumber *) index {
    
    snprintf(pkt->macsrc, ETH_LEN, "%s", __fetchMac(pkt->interface));
    snprintf(pkt->macdst, ETH_LEN, "FF:FF:FF:FF:FF:FF");
    
    uchar cbuffer[42];
    memset(cbuffer, 0, sizeof(cbuffer));
    auto uint32 size_b = (uint32) sizeof(cbuffer);
    
    /* ARP REQUEST packet */
    if (!__lookup(_data.target, (char *)[self.targetArping.text UTF8String], false, false)) return;
    [self __packing:cbuffer withSource:_data.source->sin_addr.s_addr withTarget:_data.target->sin_addr.s_addr withMacsrc:pkt->macsrc withMacdst:pkt->macdst withType:ETH_ARP withMode:ETH_ARPREQ];
    
    [Console roll:[NSString stringWithFormat:@"Arping to host [%@]:", self.targetArping.text] forInit:false toTittle:true inDump:true];
    [self __print:@""];
    [CATransaction flush];
    
    auto char err[PCAP_ERRBUF_SIZE];
    
    if ( !( __session = pcap_open_live(pkt->interface, size_b, false, 1, err)) ) {
        snprintf(ret.errmsg, 511, "On grab system interface.");
        ret.success = false;
        return;
    }
    
    __counter = 0;
    __timeout = true;
    
    while (true) {
        if ( write(pkt->bpf, cbuffer, size_b) < 0) {
            snprintf(ret.errmsg, 511, "On send packet.");
            ret.success = false;
            return;
        }
        
        pcap_loop(__session, -1, __arping_listen, NULL);
        
        if (self.stop) break;
        [NSThread sleepForTimeInterval:1.0];
    }
    
    return;
}


- (void) __macflood:(NSNumber *) index {
    
    uchar cbuffer[42];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    register uint32 __total = [self.targetMacflood.text intValue];
    register uint32 __size = sizeof(cbuffer);
    
    do {
        [Console roll:[NSString stringWithFormat:@"Mac flooding with %d packets...", __total] forInit:false toTittle:true inDump:true];
        [CATransaction flush];
        
        for (uint cnt = 0; cnt < __total; cnt++) {
            /* ARP REPLY packet */
            [self __packing:cbuffer withSource:__randomIp() withTarget:__randomIp() withMacsrc:__randomMac() withMacdst:__randomMac() withType:ETH_ARP withMode:ETH_ARPREPLY];
            
            write(pkt->bpf, cbuffer, __size);
        }
        
        [self __print:@"[Done]"];
        [self __print:@""];
        if (self.stop) break;
        
    } while (self.again.on);
    
    return;
}


- (void) __arpcannon:(NSNumber *) index {
    
    if (!__lookup(_data.source, (char *)[self.targetArpcannon1.text UTF8String], false, false)) return;
    if (!__lookup(_data.target, (char *)[self.targetArpcannon2.text UTF8String], false, false)) return;
    
    if ( hardfalse(ntohl(_data.target->sin_addr.s_addr) < ntohl(_data.source->sin_addr.s_addr)) ) {
        snprintf(ret.errmsg, 511, "Invalid range IP address");
        ret.success = false;
        return;
    }
    
    struct in_addr __magick;
    inet_pton(AF_INET, [self.targetException.text UTF8String], &__magick);
    
    [Console roll:[NSString stringWithFormat:@"Arp Cannon for %u hosts [%s to %s]:", (ntohl(_data.target->sin_addr.s_addr) - ntohl(_data.source->sin_addr.s_addr)) + (self.targetException.text.length > 0 ? 0 : 1), [self.targetArpcannon1.text UTF8String], [self.targetArpcannon2.text UTF8String]] forInit:false toTittle:true inDump:true];

    if (self.targetException.text.length > 0) {
        [Console roll:[NSString stringWithFormat:@"Excpetion IP: (%@)", self.targetException.text] forInit:false toTittle:true inDump:true];
    }
    [CATransaction flush];
    
    uchar cbuffer[42];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    register uint32 magick = ntohl(__magick.s_addr);
    register uint32 src = ntohl(_data.source->sin_addr.s_addr);
    register uint32 dst = ntohl(_data.target->sin_addr.s_addr);
    register uint32 it = 0;
    register uchar *buffer = cbuffer;
    register uint8 size = (uint32) sizeof(cbuffer);
    
    do {
        for (it = src; it <= dst; it++) {
            
            if (it == magick) continue;
            /* ARP REPLY packet */
            [self __packing:cbuffer withSource:htonl(it) withTarget:0x00000000 withMacsrc:__randomMac() withMacdst:"FF:FF:FF:FF:FF:FF" withType:ETH_ARP withMode:ETH_ARPREPLY];
            write(pkt->bpf, buffer, size);
        }

        if (self.stop) break;
    } while (true);

    [self __print:@"[Done]"];
    [self __print:@""];
    
    return;
}


- (void) run:(uint) mode {
    
    self.check = [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(__check_return) userInfo:nil repeats:YES];

    const char *month = __getmonth("__today__");
    [Console __roll:[NSString stringWithFormat:@"               Starting MpTcp %s at [%02d.%s.%02d %02d:%02d:%02d]", VERSION, _t->tm_mday, month, _t->tm_year+1900, _t->tm_hour, _t->tm_min, _t->tm_sec] forInit:true toTittle:true inDump:false];
    [Console __roll:@"                       Mptcp Project <www.hexcodes.org>" forInit:false toTittle:true inDump:false];
    [self __print:@""];
    
    memset(pkt, 0, sizeof(struct __input__));
    
    ret.success = true;
    self.stop = NO;
    [self.threads removeAllObjects];
    self->__count = 0;
    pkt->packetDisplay = (self.packetDisplay.on) ? 1 : 0;

    _data.source = (struct sockaddr_in *) addressbuff;
    _data.target = (struct sockaddr_in *) (addressbuff + sizeof(struct sockaddr_in));
    
    if (self.source.text.length > 0) {
        if ( ![self __validation_ip:[self.source.text UTF8String]] ) return;
    }
    if (!__lookup(_data.source, (char *)[self.source.text UTF8String], false, true)) return;
    
    if ( !(pkt->bpf = __checkBPF(pkt->interface)) ) {
        snprintf(ret.errmsg, 511, "On grab one valid BPF device to (%s) interface.", pkt->interface);
        ret.success = false;
        return;
    }
    
    if (mode == ARP_PING) {
        if ( ![self __validation_ip:[self.targetArping.text UTF8String]] ) return;
        
        timer = [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(__checkTimeout) userInfo:nil repeats:NO];
        
        //Pool of threads...
        for (uint index = 0; index < [self.threadsArping.text intValue]; index++ ) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__arping:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        }
        return;
    }
    
    if (mode == ARP_FLOOD) {
        if ( ![self __validation_count:[self.targetMacflood.text intValue]] ) return;
        
        for (uint index = 0; index < [self.threadsMacflood.text intValue]; index++ ) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__macflood:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        }
        
        return;
    }
    
    if (mode == ARP_CANNON) {
        if ( ![self __validation_ip:[self.targetArpcannon1.text UTF8String]] ) return;
        if ( ![self __validation_ip:[self.targetArpcannon2.text UTF8String]] ) return;
        if (self.targetException.text.length > 0) {
            if ( ![self __validation_ip:[self.targetException.text UTF8String]] ) return;
        }
        
        for (uint index = 0; index < [self.threadsArpcannon.text intValue]; index++ ) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__arpcannon:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        }
        
        return;
    }
    
    
    if (self.listen.on) {
        NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__doListen) object:nil];
        [thread start];
        return;
    }
    
    if (![self __validation_mac:pkt->macdst withMac:[self.macdst.text UTF8String]]) return;
    
    if (self.macsrc.text.length > 0) {
        if (![self __validation_mac:pkt->macsrc withMac:[self.macsrc.text UTF8String]]) return;
    } else {
        snprintf(pkt->macsrc, ETH_LEN, "%s", __fetchMac(pkt->interface));
    }
    
    if (self.target.text.length < 1) {
        if (!__lookup(_data.target, __LOOPBACK, false, false)) return;
    } else {
        if ( ![self __validation_ip:[self.target.text UTF8String]] ) return;
        if (!__lookup(_data.target, (char *)[self.target.text UTF8String], false, false)) return;
    }
    
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
