//
//  Tcp.m
//  Mptcptmp
//
//  Created by Felipe Ecker on 25/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import "Tcp.h"

static struct __data _data;   /* Sender bulk */

@implementation Tcp

- (id) init {
    self = [super init];
    
    if (self) {
        self.types = @[
                       @"TCP SYN",
                       @"TCP ACK",
                       @"TCP RST",
                       @"TCP FIN",
                       @"TCP PSH",
                       @"TCP XMAS",
                       @"TCP NULL",
                       @"TCP Connect"];
        
        self.pickerNumberComponents = 1;
        self.pickerNumberRows = [self.types count];
        
        self.threads = [NSMutableArray arrayWithCapacity:50];
    }
    return self;
}


- (void) ReturnKeyboard {
    [self.target resignFirstResponder];
    [self.source resignFirstResponder];
    [self.port resignFirstResponder];
    [self.srcPort resignFirstResponder];
}


- (void)editChanged {  
    if ( (self.listen.on || self.listenConn.on) && (self.srcPort.text.length > 0) ) {
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
    
    if (self.listen.on || self.listenConn.on) {
        self.target.enabled = NO;
        [self.target setAlpha:.6];
        self.port.enabled = NO;
        [self.port setAlpha:.6];
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
        if (self.listenConn.on) self.packetDisplay.enabled = NO;
        if (self.srcPort.text.length > 0) self.start.enabled = YES;
    } else {
        self.target.enabled = YES;
        [self.target setAlpha:1];
        self.port.enabled = YES;
        [self.port setAlpha:1];
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
        if (self.target.text.length < 2 || self.port.text.length < 1) self.start.enabled = NO;
        else self.start.enabled = YES;
    }
    
    if (self.flood.on) {
        self.again.enabled = NO;
        self.listen.enabled = NO;
        self.listenConn.enabled = NO;
        self.noReplies.enabled = NO;
        self.countSlider.enabled = NO;
        self.packetDisplay.enabled = NO;
        self.threadsSlider.enabled = YES;
    } else {
        if (!self.listen.on && !self.listenConn.on) self.again.enabled = YES;
        self.listen.enabled = YES;
        self.listenConn.enabled = YES;
        self.noReplies.enabled = YES;
        if (!self.listen.on && !self.listenConn.on) self.countSlider.enabled = YES;
        if (!self.listenConn.on) self.packetDisplay.enabled = YES;
        self.threadsSlider.enabled = NO;
    }
    
    if (self.packetDisplay.on) {
        self.noReplies.enabled = NO;
    }
    else {
        if(self.listen.on || self.listenConn.on || self.flood.on) self.noReplies.enabled = NO;
        else self.noReplies.enabled = YES;
    }
    
    if (self.noReplies.on) {
        self.packetDisplay.enabled = NO;
    }
    else {
        if (self.flood.on) self.packetDisplay.enabled = NO;
        else if (!self.listenConn.on) self.packetDisplay.enabled = YES;
    }
    
    if (self.listen.on) self.listenConn.enabled = NO;
    if (self.listenConn.on) self.listen.enabled = NO;
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


const char *__tagging(struct tcphdr *__tcp) {
    
    static char __buff[64];
    memset(__buff, 0, sizeof(__buff));
    
    if (!__tcp->th_flags) snprintf(__buff, 11, "NULL FLAGS");
    else {
        if (__tcp->th_flags & TCP_RST) snprintf(__buff, 5, "|RST");
        if (__tcp->th_flags & TCP_FIN) strncat(__buff, "|FIN", 4);
        if (__tcp->th_flags & TCP_PSH) strncat(__buff, "|PSH", 4);
        if (__tcp->th_flags & TCP_ACK) strncat(__buff, "|ACK", 4);
        if (__tcp->th_flags & TCP_SYN) strncat(__buff, "|SYN", 4);
        if (__tcp->th_flags & TCP_URG) strncat(__buff, "|URG", 4);
    }
    
    return __buff;
}


- (void) __doListenConnections {

    uchar recvbuff[[self.size.text intValue] + BIGBUFF];
    char address[INET_ADDRSTRLEN];
    
    struct sockaddr_in remote;
    unsigned size = sizeof(struct sockaddr_in);
    signed int sock, nsock, __input = 0;
    
    auto struct timeval _times;
    auto fd_set arrived;
    
    [Console __roll:[NSString stringWithFormat:@"Listening for TCP connections on local port (%d):", [self.srcPort.text intValue]] forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    
    do {
        // TCP STREAM socket
        if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) return;
    
        if ( (bind(sock, (struct sockaddr *) _data.source,
                   sizeof(struct sockaddr))) < 0) {
            snprintf(ret.errmsg, 511, "On listen connections. Restart the Mptcp.");
            ret.success = false;
            return;
        }
    
        if (listen(sock, 1) < 0) {
            snprintf(ret.errmsg, 511, "On listen actions. Restart the Mptcp.");
            ret.success = false;
            return;
        }
    
        if ( (nsock = accept(sock, (struct sockaddr *) &remote, &size)) <= 0){
            snprintf(ret.errmsg, 511, "On accept connection. Restart the Mptcp.");
            ret.success = false;
            return;
        }
    
        close(sock);
        sock = nsock;
        __sysdate();
    
        inet_ntop(AF_INET, &(remote.sin_addr), address, INET_ADDRSTRLEN);
        [self __print:@""];
        [self __print:[NSString stringWithFormat:@"(%02d:%02d:%02d) Connected: Opened by host [%s]", _t->tm_hour, _t->tm_min, _t->tm_sec, address]];
        [CATransaction flush];
        

        _times.tv_sec = 0;
        _times.tv_usec = 500;
        FD_ZERO(&arrived);
        FD_SET(STDIN_FILENO, &arrived);
    
        if ( !select(STDIN_FILENO+1, &arrived, NULL, NULL, &_times)) pass;
        else
            while ( (__input = read(STDIN_FILENO, &recvbuff, BIGBUFF)) > 0)
                write(sock, &recvbuff, __input);
    
        FD_ZERO(&arrived);
        FD_SET(sock, &arrived);

        while ( FD_ISSET (sock, &arrived)) {
            memset(recvbuff, 0, sizeof(recvbuff));
            select(sock+1, &arrived, NULL, NULL, NULL);
        
            if ( ( __input = read(sock, recvbuff, sizeof(recvbuff))) <= 0 ) FD_CLR(sock, &arrived);
            else {
                [self __print:[NSString stringWithFormat:@"%s", recvbuff]];
                [CATransaction flush];
            }
            
            if (FD_ISSET (STDIN_FILENO, &arrived))
                if ( read (STDIN_FILENO, recvbuff, sizeof(recvbuff)) <= 0 ) FD_CLR(sock, &arrived);
        }

        [Console __roll:@"[Connection closed]. Listening again.." forInit:false toTittle:true inDump:true];
        [CATransaction flush];
        close(sock);

        sleep(2);
    } while (!self.stop);
    return;
}


static void __bsd_listen ( uchar *args,
                          const struct pcap_pkthdr *hdr,
                          const uchar *recvbuff )
{
    
    auto struct ip *ip      = (struct ip *) (recvbuff + SIZE_ETH);
    auto struct tcphdr *tcp = (struct tcphdr *) (recvbuff + SIZE_IP+ SIZE_ETH);
    
    __sysdate();
    auto char aux[256], address[INET_ADDRSTRLEN];
    
    if (ip->ip_p != IPPROTO_TCP) return;
    if ((args) && (_data.target->sin_addr.s_addr != ip->ip_src.s_addr) ) return;
    if ((args) && pkt->port == ntohs(tcp->th_sport) ) goto __CATCHED;
    if ( ntohs(tcp->th_dport) != pkt->srcport ) return;
    
__CATCHED:
    memset(aux, 0, sizeof(aux));
    inet_ntop(AF_INET, &(ip->ip_src), address, INET_ADDRSTRLEN);
    
    const char *type = __tagging(tcp);
    if (!args) snprintf(aux, sizeof(aux) -1 , "(%02d:%02d:%02d) Received TCP %s packet from (%s)", _t->tm_hour, _t->tm_min, _t->tm_sec, type, address);
    else snprintf(aux, sizeof(aux) -1 , "  --> Received TCP %s packet from (%s)", type, address);
    
    [Console roll:[NSString stringWithFormat:@"%s", aux] forInit:false toTittle:false inDump:false];
    [Console roll:@"" forInit:false toTittle:false inDump:false];
    [CATransaction flush];
    
    if (pkt->packetDisplay) __show_packet(&recvbuff[14], ntohs(ip->ip_len));
    [CATransaction flush];
    
    return;
}


- (void) __doListen {
    
    [Console __roll:[NSString stringWithFormat:@"Listening for TCP data on local port (%d):", [self.srcPort.text intValue]] forInit:false toTittle:true inDump:true];
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


- (void) __doSimpleConnection:(NSNumber *) index {
    
    uint32 sock;
    
    /* TCP STREAM socket */
    if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) return;
    
    unsigned __sizeof = sizeof(struct sockaddr);
    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);
    
    [Console __roll:[NSString stringWithFormat:@"Connecting to [%s] on port %d...", address, [self.port.text intValue]] forInit:false toTittle:true inDump:true];
    [self __print:@""];
    
    auto char buff[BIGBUFF];
    auto struct timeval _times;
    auto fd_set beep;
    register signed int __input = 0;
    
    __sysdate();
    _times.tv_sec = 1;
    _times.tv_usec = 0;
    FD_ZERO(&beep);
    FD_SET(sock, &beep);
    
    if ( connect(sock, (struct sockaddr *) _data.target, __sizeof) < 0) {
        snprintf(ret.errmsg, 511, "Unable to connect on host. Connection refused.");
        ret.success = false;
        return;
    }
    
    [self __print:[NSString stringWithFormat:@"(%02d:%02d:%02d) Connected on Host [%s]:", _t->tm_hour, _t->tm_min, _t->tm_sec, address]];
    [CATransaction flush];
    
    while ( select(sock+1, &beep, NULL, NULL, &_times) ) {
        __input = read(sock, &buff, BIGBUFF);
        
        [self __print:[NSString stringWithFormat:@"%s", buff]];
        [CATransaction flush];
    }
    
    [Console __roll:@"[Closed connection]." forInit:false toTittle:true inDump:true];
    [CATransaction flush];
    
    close(sock);
    return;
}


- (struct tcphdr *) __packing:(uchar *) __buffer withSize:(uint16) __size
                                        atSource:(const struct sockaddr_in *) __source
                                        atTarget:(const struct sockaddr_in *) __target
{
    
    struct ip *__ip = (struct ip *) __buffer;
    struct tcphdr *__tcp = (struct tcphdr *) (__buffer + SIZE_IP);
    
    struct __auxhdr {
        uint32 saddr;
        uint32 daddr;
        uint8 useless;
        uint8 proto;
        uint16 tcpsiz;
        struct tcphdr tcp;
        uchar data[1];
    };
    
    struct __auxhdr *tcpaux = (struct __auxhdr *) calloc(1, sizeof(struct __auxhdr) + (__size - 1));
    
    __ip->ip_src   = __source->sin_addr;
    __ip->ip_dst   = __target->sin_addr;
    __ip->ip_v     = 0x04;
    __ip->ip_off   = 0x00;
    __ip->ip_hl    = 0x05;
    __ip->ip_ttl   = [self.ttl.text intValue];
    __ip->ip_id    = htons(rand() % 0XFFFF);
    __ip->ip_p     = IPPROTO_TCP;
    __ip->ip_len   = __size; /* HeaderIP and headerTCP --> 40 bytes */
    __ip->ip_sum   = __checksum((uint16 *) __ip, SIZE_IP);
    
    __tcp->th_sport= __source->sin_port;
    __tcp->th_dport= __target->sin_port;
    __tcp->th_seq  = (pkt->tcpType & TCP_SYN) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
    __tcp->th_ack  = (pkt->tcpType & TCP_ACK) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
    __tcp->th_x2   = 0x0;
    __tcp->th_off  = 0x5;
    __tcp->th_flags |= (pkt->tcpType & TCP_FIN) ? TCP_FIN : 0x00;
    __tcp->th_flags |= (pkt->tcpType & TCP_SYN) ? TCP_SYN : 0x00;
    __tcp->th_flags |= (pkt->tcpType & TCP_RST) ? TCP_RST : 0x00;
    __tcp->th_flags |= (pkt->tcpType & TCP_PSH) ? TCP_PSH : 0x00;
    __tcp->th_flags |= (pkt->tcpType & TCP_ACK) ? TCP_ACK : 0x00;
    __tcp->th_flags |= (pkt->tcpType & TCP_URG) ? TCP_URG : 0x00;
    __tcp->th_win   = htons(1024);
    /* I'll set size window to 1024. Don't care about is. */
    __tcp->th_urp   = 0x00;
    __tcp->th_sum   = 0;
    
    tcpaux->saddr    = __ip->ip_src.s_addr;
    tcpaux->daddr    = __ip->ip_dst.s_addr;
    tcpaux->useless  = 0x0;
    tcpaux->proto    = IPPROTO_TCP;
    tcpaux->tcpsiz   = htons(__size - SIZE_IP);
    
    memcpy(&(tcpaux->tcp), __tcp, SIZE_TCP);
    __tcp->th_sum   = __checksum( (uint16 *) tcpaux, (__size - SIZE_IP));

    free(tcpaux);
    return __tcp;
}


- (void) __doResponse {
    
    auto char *eth, err_buff[PCAP_ERRBUF_SIZE];
    void *__breakout = (void *) 0xFF;

    if ( !(eth = pcap_lookupdev(err_buff)) ) {
        snprintf(ret.errmsg, 511, "On grab system's interface. Detail: %s", err_buff);
        ret.success = false;
        return;
    }
    
    if ( !(__session = pcap_open_live(eth, [self.size.text intValue] + 128, false, 1, err_buff)) ) {
        snprintf(ret.errmsg, 511, "Couldn't open device %s. Detail: %s", eth, err_buff);
        ret.success = false;
        return;
    }
    
    pcap_loop(__session, -1, __bsd_listen, __breakout);
    return;
}


- (void) __send:(NSNumber *) index {
    
    uint32 sock;
    
    /* RAW socket*/
    if ( !( sock  = __socketPool(true, 0, false)) ) return;
    __set_hdrincl(sock);
        
    uchar cbuffer[[self.size.text intValue] + 52];
    memset(cbuffer, 0, sizeof(cbuffer));
        
    struct tcphdr *__tcp = [self __packing:cbuffer withSize:(uint16)sizeof(cbuffer) atSource:_data.source atTarget:_data.target];
    
    register uint count = [self.count.text intValue];
    unsigned _sizeof = sizeof(struct sockaddr_in);
    
    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);
    
    if (!self.noReplies.on) [self performSelectorInBackground:@selector(__doResponse) withObject:nil];
    const char *type;
    do {
        
        type = __tagging(__tcp);
        [self __print:[NSString stringWithFormat:@"(%d) Sending TCP %s to [%s] on port %d", self->__count++, type, address, [self.port.text intValue]]];
        
        if ( hardfalse(sendto(sock, cbuffer, sizeof(cbuffer), 0, (struct sockaddr *) _data.target, _sizeof) < 0) ) {
            snprintf(ret.errmsg, 511, "On send TCP packets. Restart the Mptcp.");
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


-(void) __burst:(NSNumber *) index {
        
    register uint32 sock;
    
    /* RAW socket */
    if ( !( sock = __socketPool(true, 0, false)) ) return;
    __set_hdrincl(sock);
    
    uchar cbuffer[[self.size.text intValue] + 52];
    memset(cbuffer, 0, sizeof(cbuffer));
    
    struct tcphdr *__tcp = [self __packing:cbuffer withSize:(uint16) sizeof(cbuffer) atSource:_data.source atTarget:_data.target];
        
    auto char address[INET_ADDRSTRLEN] __nocommon__;
    inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);
    
    const char *type = __tagging(__tcp);
    [self __print:[NSString stringWithFormat:@"[BURST] Sending TCP (%s) to [%s] on port %d..", type, address, [self.port.text intValue]]];

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
        [self __packing:cbuffer withSize:(uint16) sizeof(cbuffer) atSource:_data.source atTarget:_data.target];
    } while (!self.stop);

    return;
}


- (void) run {
    self.check = [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(__check_return) userInfo:nil repeats:YES];
    
    memset(pkt, 0, sizeof(struct __input__));
    
    if ([self.type.text isEqual:@"TCP Connect"]) pkt->tcpType |= TCP_CON;
    else if ([self.type.text isEqualToString:@"TCP SYN"]) pkt->tcpType |= TCP_SYN;
    else if ([self.type.text isEqualToString:@"TCP ACK"]) pkt->tcpType |= TCP_ACK;
    else if ([self.type.text isEqualToString:@"TCP FIN"]) pkt->tcpType |= TCP_FIN;
    else if ([self.type.text isEqualToString:@"TCP RST"]) pkt->tcpType |= TCP_RST;
    else if ([self.type.text isEqualToString:@"TCP PSH"]) pkt->tcpType |= TCP_PSH;
    else if ([self.type.text isEqualToString:@"TCP XMAS"]) { pkt->tcpType |= TCP_FIN; pkt->tcpType |= TCP_PSH; pkt->tcpType |= TCP_URG; }
    else if ([self.type.text isEqualToString:@"TCP NULL"]) pkt->tcpType |= TCP_NULL;
    else pkt->tcpType = TCP_SYN;
    
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
    
    if (self.listenConn.on) {
        NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__doListenConnections) object:nil];
        [thread start];
        return;
    }
    
    if (!__lookup(_data.target, (char *)[self.target.text UTF8String], [self.port.text intValue], false)) return;
    
    //Pool of threads...
    for (uint index = 0; index < [self.threadsLabel.text intValue]; index++ ) {
        if (pkt->tcpType & TCP_CON) {
            NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__doSimpleConnection:) object:[NSNumber numberWithUnsignedInt:index]];
            [self.threads insertObject:thread atIndex:index];
            [thread start];
        } else if (self.flood.on) {
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
