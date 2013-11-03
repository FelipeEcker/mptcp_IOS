//
//  ViewController.m
//  Mptcp
//
//  Created by Felipe Ecker on 09/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import "ViewController.h"

extern UITableView *console;

#define INFO_SIZE 680
#define ICMP_SIZE 680
#define TCP_SIZE 720
#define UDP_SIZE 540
#define ARP_SIZE 1380
#define WEB_SIZE 540
#define IRC_SIZE 480


@implementation ViewController

- (IBAction)ReturnKeyboard:(id)sender {
    [sender resignFirstResponder];
}

- (IBAction)docBtn:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"http://www.hexcodes.org/mptcp.i"]];
}

- (IBAction)homeBtn:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"http://www.hexcodes.org"]];
}

- (IBAction)aboutBtn:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, INFO_SIZE)];
    self.infoView.hidden = NO;
    self.backBtn.hidden = NO;
    self.infoBtn.hidden = YES;
    self.modesBar.hidden = YES;
    if (screen == ICMP_VIEW) self.icmpView.hidden = YES;
    else if (screen == TCP_VIEW) self.tcpView.hidden = YES;
    else if (screen == UDP_VIEW) self.udpView.hidden = YES;
    else if (screen == ARP_VIEW) self.arpView.hidden = YES;
    else if (screen == WEB_VIEW) self.webView.hidden = YES;
    else if (screen == IRC_VIEW) self.ircView.hidden = YES;
    else pass;
}

- (IBAction)aboutBack:(id)sender {
    self.modesBar.hidden = NO;
    self.infoBtn.hidden = NO;
    self.backBtn.hidden = YES;
    self.infoView.hidden = YES;
    if (screen == ICMP_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, ICMP_SIZE)];
        self.icmpView.hidden = NO;
    } else if (screen == TCP_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, TCP_SIZE)];
        self.tcpView.hidden = NO;
    } else if (screen == UDP_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, UDP_SIZE)];
        self.udpView.hidden = NO;
    } else if (screen == ARP_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, ARP_SIZE)];
        self.arpView.hidden = NO;
    } else if (screen == WEB_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, WEB_SIZE)];
        self.webView.hidden = NO;
    } else if (screen == IRC_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, IRC_SIZE)];
        self.ircView.hidden = NO;
    } else pass;
}

- (IBAction)stopConsole:(id)sender {
    self.resultView.hidden = YES;
    self.navbar.hidden = NO;
    
    if (screen == ICMP_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, ICMP_SIZE)];
        self.icmpView.hidden = NO;
        [icmp doStop];
    } else if (screen == TCP_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, TCP_SIZE)];
        self.tcpView.hidden = NO;
        [tcp doStop];
    } else if (screen == UDP_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, UDP_SIZE)];
        self.udpView.hidden = NO;
        [udp doStop];
    } else if (screen == ARP_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, ARP_SIZE)];
        self.arpView.hidden = NO;
        [arp doStop];
    } else if (screen == WEB_VIEW) {
        [self.scroller setContentSize:CGSizeMake(320, WEB_SIZE)];
        self.webView.hidden = NO;
        [web doStop];
    } else self.infoView.hidden = YES;
}

- (IBAction)clearConsole:(id)sender {
    [Console roll:@"" forInit:true toTittle:false inDump:false];
}

- (IBAction)changeModes:(UISegmentedControl *)sender {

    switch (sender.selectedSegmentIndex) {
        case ICMP_VIEW: {
            screen = ICMP_VIEW;
            [self.scroller setContentSize:CGSizeMake(320, ICMP_SIZE)];
            self.icmpView.hidden = NO;
            self.tcpView.hidden = YES;
            self.udpView.hidden = YES;
            self.arpView.hidden = YES;
            self.webView.hidden = YES;
            self.ircView.hidden = YES;
            [self.icmpPicker reloadAllComponents];
            break;
        
        } case TCP_VIEW: {
            screen = TCP_VIEW;
            [self.scroller setContentSize:CGSizeMake(320, TCP_SIZE)];
            self.tcpView.hidden = NO;
            self.icmpView.hidden = YES;
            self.udpView.hidden = YES;
            self.arpView.hidden = YES;
            self.webView.hidden = YES;
            self.ircView.hidden = YES;
            [self.tcpPicker reloadAllComponents];
            break;
        
        } case UDP_VIEW: {
            screen = UDP_VIEW;
            [self.scroller setContentSize:CGSizeMake(320, UDP_SIZE)];
            self.udpView.hidden = NO;
            self.tcpView.hidden = YES;
            self.icmpView.hidden = YES;
            self.arpView.hidden = YES;
            self.webView.hidden = YES;
            self.ircView.hidden = YES;
            break;
        
        } case ARP_VIEW: {
            screen = ARP_VIEW;
            [self.scroller setContentSize:CGSizeMake(320, ARP_SIZE)];
            self.arpView.hidden = NO;
            self.tcpView.hidden = YES;
            self.icmpView.hidden = YES;
            self.udpView.hidden = YES;
            self.webView.hidden = YES;
            self.ircView.hidden = YES;
            [self.arpPicker reloadAllComponents];
            break;
        } case WEB_VIEW: {
            screen = WEB_VIEW;
            [self.scroller setContentSize:CGSizeMake(320, WEB_SIZE)];
            self.webView.hidden = NO;
            self.udpView.hidden = YES;
            self.tcpView.hidden = YES;
            self.icmpView.hidden = YES;
            self.arpView.hidden = YES;
            self.ircView.hidden = YES;
            break;
        } case IRC_VIEW: {
            screen = IRC_VIEW;
            [self.scroller setContentSize:CGSizeMake(320, IRC_SIZE)];
            self.ircView.hidden = NO;
            self.udpView.hidden = YES;
            self.tcpView.hidden = YES;
            self.icmpView.hidden = YES;
            self.arpView.hidden = YES;
            self.webView.hidden = YES;
            break;
        }
            
        default: break;
    }
}

- (IBAction)editChanged:(id)sender{
    if (screen == ICMP_VIEW) [icmp editChanged];
    else if (screen == TCP_VIEW) [tcp editChanged];
    else if (screen == UDP_VIEW) [udp editChanged];
    else if (screen == ARP_VIEW) [arp editChanged];
    else if (screen == WEB_VIEW) [web editChanged];
    else if (screen == IRC_VIEW) [irc editChanged];
    else pass;
}

- (NSInteger) numberOfComponentsInPickerView:(UIPickerView *)pickerView {
    if (screen == ICMP_VIEW) return icmp.pickerNumberComponents;
    else if (screen == TCP_VIEW) return tcp.pickerNumberComponents;
    else if (screen == ARP_VIEW) return arp.pickerNumberComponents;
    else return 1;
}

- (NSInteger) pickerView:(UIPickerView *)pickerView numberOfRowsInComponent:(NSInteger)component {
    if (screen == ICMP_VIEW) return icmp.pickerNumberRows;
    else if (screen == TCP_VIEW) return tcp.pickerNumberRows;
    else if (screen == ARP_VIEW) return arp.pickerNumberRows;
    else return 1;
}

- (NSString *) pickerView:(UIPickerView *)pickerView titleForRow:(NSInteger)row forComponent:(NSInteger)component {
    if (screen == ICMP_VIEW) return [icmp pickerTitle:row];
    else if (screen == TCP_VIEW) return [tcp pickerTitle:row];
    else if (screen == ARP_VIEW) return [arp pickerTitle:row inComponent:component];
    else return @"NONE";
}

- (void) pickerView:(UIPickerView *)pickerView didSelectRow:(NSInteger)row inComponent:(NSInteger)component {
    if (screen == ICMP_VIEW) [icmp pickerSelectedRow:row];
    else if (screen == TCP_VIEW) [tcp pickerSelectedRow:row];
    else if (screen == ARP_VIEW) [arp pickerSelectedRow:row inComponent:(NSInteger) component];
    else NSLog(@"NONE");
}

- (CGFloat) pickerView:(UIPickerView *)pickerView widthForComponent:(NSInteger)component {
    if (screen == ARP_VIEW) {
        if (component == 0) return 80.0;
        return 100.0;
    }
    return 180.0;
}


#pragma mark - UITableViewDataSource
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return 16;
}


- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    
    UITableViewCell *cell = [[UITableViewCell alloc] init];
    cell.textLabel.text = [NSString stringWithFormat:@"None"];
    return cell;
}

- (void) init_icmp {
    icmp = [[Icmp alloc] init];

    icmp.target = self.icmpTarget;
    icmp.source = self.icmpSource;
    icmp.type = self.icmpType;
    icmp.picker = self.icmpPicker;
    icmp.listen = self.icmpListen;
    icmp.again = self.icmpAgain;
    icmp.flood = self.icmpFlood;
    icmp.noReplies = self.icmpNoReplies;
    icmp.packetDisplay = self.icmpPacketDisplay;
    icmp.ttlSlider = self.icmpTtlSlider;
    icmp.countSlider = self.icmpCountSlider;
    icmp.sizeSlider = self.icmpSizeSlider;
    icmp.threadsSlider = self.icmpThreadsSlider;
    icmp.ttl = self.icmpTtl;
    icmp.count = self.icmpCount;
    icmp.size = self.icmpSize;
    icmp.threadsLabel = self.icmpThreads;
    icmp.start = self.icmpStart;
}

- (void) init_tcp {
    tcp = [[Tcp alloc] init];

    tcp.target = self.tcpTarget;
    tcp.source = self.tcpSource;
    tcp.port = self.tcpPort;
    tcp.srcPort = self.tcpSrcPort;
    tcp.type = self.tcpType;
    tcp.picker = self.tcpPicker;
    tcp.listenConn = self.tcpListenConn;
    tcp.listen = self.tcpListen;
    tcp.again = self.tcpAgain;
    tcp.flood = self.tcpFlood;
    tcp.noReplies = self.tcpNoReplies;
    tcp.packetDisplay = self.tcpPacketDisplay;
    tcp.ttlSlider = self.tcpTtlSlider;
    tcp.countSlider = self.tcpCountSlider;
    tcp.sizeSlider = self.tcpSizeSlider;
    tcp.threadsSlider = self.tcpThreadsSlider;
    tcp.ttl = self.tcpTtl;
    tcp.count = self.tcpCount;
    tcp.size = self.tcpSize;
    tcp.threadsLabel = self.tcpThreads;
    tcp.start = self.tcpStart;
}

- (void) init_udp {
    udp = [[Udp alloc] init];

    udp.target = self.udpTarget;
    udp.source = self.udpSource;
    udp.port = self.udpPort;
    udp.srcPort = self.udpSrcPort;
    udp.listen = self.udpListen;
    udp.again = self.udpAgain;
    udp.flood = self.udpFlood;
    udp.packetDisplay = self.udpPacketDisplay;
    udp.ttlSlider = self.udpTtlSlider;
    udp.countSlider = self.udpCountSlider;
    udp.sizeSlider = self.udpSizeSlider;
    udp.threadsSlider = self.udpThreadsSlider;
    udp.ttl = self.udpTtl;
    udp.count = self.udpCount;
    udp.size = self.udpSize;
    udp.threadsLabel = self.udpThreads;
    udp.start = self.udpStart;
}

- (void) init_arp {
    arp = [[Arp alloc] init];

    arp.target = self.arpTarget;
    arp.source = self.arpSource;
    arp.macsrc = self.arpMacsrc;
    arp.macdst = self.arpMacdst;
    arp.typeA = self.arpTypeA;
    arp.typeB = self.arpTypeB;
    arp.picker = self.arpPicker;
    arp.listen = self.arpListen;
    arp.again = self.arpAgain;
    arp.flood = self.arpFlood;
    arp.packetDisplay = self.arpPacketDisplay;
    arp.threadsSlider = self.arpThreadsSlider;
    arp.threadsLabel = self.arpThreads;
    arp.broadcast = self.arpBroadcast;
    arp.targetArping = self.arpTargetArping;
    arp.threadsSliderArping = self.arpThreadsSliderArping;
    arp.targetMacflood = self.arpTargetMacflood;
    arp.threadsSliderMacflood = self.arpThreadsSliderMacflood;
    arp.targetArpcannon1 = self.arpTargetArpcannon1;
    arp.targetArpcannon2 = self.arpTargetArpcannon2;
    arp.targetException = self.arpTargetException;
    arp.threadsSliderArpcannon = self.arpThreadsSliderArpcannon;
    arp.threadsArping = self.arpThreadsArping;
    arp.threadsMacflood = self.arpThreadsMacflood;
    arp.threadsArpcannon = self.arpThreadsArpcannon;
    arp.start = self.arpStart;
    arp.startArping = self.arpStartArping;
    arp.startMacflood = self.arpStartMacflood;
    arp.startArpcannon = self.arpStartArpcannon;
}

- (void) init_web {
    web = [[Web alloc] init];
    
    web.target = self.webTarget;
    web.port = self.webPort;
    web.http = self.webHttp;
    web.tcpconn = self.webTcpconn;
    web.tcpsyn = self.webTcpsyn;
    web.tcpack = self.webTcpack;
    web.icmp = self.webIcmp;
    web.udp = self.webUdp;
    web.threadsSlider = self.webThreadsSlider;
    web.threadsLabel = self.webThreads;
    web.start = self.webStart;
}

- (void) init_irc {
    irc = [[Irc alloc] init];
    
    irc.target = self.ircTarget;
    irc.port = self.ircPort;
    irc.channel = self.ircChannel;
    irc.password = self.ircPassword;
    irc.start = self.ircStart;
    irc.statusMessage = self.ircStatusMessage;
    irc.statusProgress = self.ircStatusProgress;
    irc.running = NO;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self.scroller setContentSize:CGSizeMake(320, ICMP_SIZE)];
    [self.scroller setScrollEnabled:YES];
    console = self.console;
    screen = ICMP_VIEW;
    
    self.resultView.transform = CGAffineTransformIdentity;
    self.resultView.transform = CGAffineTransformMakeRotation(M_PI/2);
    self.resultView.bounds = CGRectMake(0, 0, 480, 320);
    [UIView commitAnimations];
    
    srand(time(NULL));
    [self init_icmp];
    [self init_tcp];
    [self init_udp];
    [self init_arp];
    [self init_web];
    [self init_irc];
}

// ICMP Stuff......................................
- (IBAction)ReturnKeyboardFromIcmpView:(id)sender {
    [icmp ReturnKeyboard];
}

- (IBAction)icmpChangeTtl:(id)sender {
    return [icmp changeTtl];
}

- (IBAction)icmpChangeCount:(id)sender {
    return [icmp changeCount];
}

- (IBAction)icmpChangeSize:(id)sender {
    return [icmp changeSize];
}

- (IBAction)icmpChangeThreads:(id)sender {
    return [icmp changeThreads];
}

- (IBAction)icmpChangeStates:(id)sender {
    return [icmp changeStates];
}

- (IBAction)icmpStart:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, 440)];
    self.resultView.hidden = NO;
    self.icmpView.hidden = YES;
    self.navbar.hidden = YES;

    return [icmp run];
}

// TCP Stuff.......................................
- (IBAction)ReturnKeyboardFromTcpView:(id)sender {
    [tcp ReturnKeyboard];
}

- (IBAction)tcpChangeTtl:(id)sender {
    return [tcp changeTtl];
}

- (IBAction)tcpChangeCount:(id)sender {
    return [tcp changeCount];
}

- (IBAction)tcpChangeSize:(id)sender {
    return [tcp changeSize];
}

- (IBAction)tcpChangeThreads:(id)sender {
    return [tcp changeThreads];
}

- (IBAction)tcpChangeStates:(id)sender {
    return [tcp changeStates];
}

- (IBAction)tcpStart:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, 440)];
    self.resultView.hidden = NO;
    self.tcpView.hidden = YES;
    self.navbar.hidden = YES;
    
    return [tcp run];
}

// UDP Stuff.......................................
- (IBAction)ReturnKeyboardFromUdpView:(id)sender {
    [udp ReturnKeyboard];
}

- (IBAction)udpChangeTtl:(id)sender {
    return [udp changeTtl];
}

- (IBAction)udpChangeCount:(id)sender {
    return [udp changeCount];
}

- (IBAction)udpChangeSize:(id)sender {
    return [udp changeSize];
}

- (IBAction)udpChangeThreads:(id)sender {
    return [udp changeThreads];
}

- (IBAction)udpChangeStates:(id)sender {
    return [udp changeStates];
}

- (IBAction)udpStart:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, 440)];
    self.resultView.hidden = NO;
    self.udpView.hidden = YES;
    self.navbar.hidden = YES;
    
    return [udp run];
}

// ARP Stuff.......................................
- (IBAction)ReturnKeyboardFromArpView:(id)sender {
    [arp ReturnKeyboard];
}

- (IBAction)arpChangeThreads:(id)sender {
    return [arp changeThreads];
}

- (IBAction)arpChangeStates:(id)sender {
    return [arp changeStates];
}

- (IBAction)arpSetBroadcast:(id)sender {
    [arp setBroadcast];
}

- (IBAction) arpChangeThreadsArping:(id)sender {
    [arp changeThreadsArping];
}

- (IBAction) arpChangeThreadsMacflood:(id)sender {
    [arp changeThreadsMacflood];
}

- (IBAction) arpChangeThreadsArpcannon:(id)sender {
    [arp changeThreadsArpcannon];
}

- (IBAction)arpStart:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, 440)];
    self.resultView.hidden = NO;
    self.arpView.hidden = YES;
    self.navbar.hidden = YES;
    
    #define ARPSEND 0x00
    return [arp run:ARPSEND];
}

- (IBAction)arpStartArping:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, 440)];
    self.resultView.hidden = NO;
    self.arpView.hidden = YES;
    self.navbar.hidden = YES;
    
    return [arp run:ARP_PING];
}

- (IBAction)arpStartMacflood:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, 440)];
    self.resultView.hidden = NO;
    self.arpView.hidden = YES;
    self.navbar.hidden = YES;
    
    return [arp run:ARP_FLOOD];
}

- (IBAction)arpStartArpcannon:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, 440)];
    self.resultView.hidden = NO;
    self.arpView.hidden = YES;
    self.navbar.hidden = YES;
    
    return [arp run:ARP_CANNON];
}

// UDP Stuff.......................................
- (IBAction)ReturnKeyboardFromWebView:(id)sender {
    [web ReturnKeyboard];
}

- (IBAction)webChangeThreads:(id)sender {
    return [web changeThreads];
}

- (IBAction)webChangeStates:(id)sender {
    return [web changeStates];
}

- (IBAction)webStart:(id)sender {
    [self.scroller setContentSize:CGSizeMake(320, 440)];
    self.resultView.hidden = NO;
    self.webView.hidden = YES;
    self.navbar.hidden = YES;
    
    return [web run];
}

// UDP Stuff.......................................
- (IBAction)ReturnKeyboardFromIrcView:(id)sender {
    [irc ReturnKeyboard];
}

- (IBAction)ircStart:(id)sender {
    self.ircStatusView.hidden = NO;
    if (!irc.running) [irc run];
    
    return;
}

- (IBAction)ircStop:(id)sender {
    self.ircStatusView.hidden = YES;
    [irc doStop];
}

   
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
}

- (void)viewDidUnload {
    [self setNavbar:nil];
    [self setConsole:nil];
    [self setScroller:nil];
    [self setInfoView:nil];
    [self setModesBar:nil];
    [self setBackBtn:nil];
    [self setInfoBtn:nil];
    [self setResultView:nil];
    [self setStopBtn:nil];
    [self setClearBtn:nil];
    
    [self setIcmpView:nil];
    [self setIcmpTarget:nil];
    [self setIcmpSource:nil];
    [self setIcmpType:nil];
    [self setIcmpTtlSlider:nil];
    [self setIcmpCountSlider:nil];
    [self setIcmpSizeSlider:nil];
    [self setIcmpThreadsSlider:nil];
    [self setIcmpTtl:nil];
    [self setIcmpCount:nil];
    [self setIcmpSize:nil];
    [self setIcmpThreads:nil];
    [self setIcmpStart:nil];
    [self setIcmpAgain:nil];
    [self setIcmpFlood:nil];
    [self setIcmpNoReplies:nil];
    [self setIcmpPacketDisplay:nil];
    [self setIcmpListen:nil];
    [self setIcmpPicker:nil];
    
    [self setTcpView:nil];
    [self setTcpTarget:nil];
    [self setTcpSource:nil];
    [self setTcpPort:nil];
    [self setTcpSrcPort:nil];
    [self setTcpType:nil];
    [self setTcpTtlSlider:nil];
    [self setTcpCountSlider:nil];
    [self setTcpSizeSlider:nil];
    [self setTcpThreadsSlider:nil];
    [self setTcpTtl:nil];
    [self setTcpCount:nil];
    [self setTcpSize:nil];
    [self setTcpThreads:nil];
    [self setTcpStart:nil];
    [self setTcpAgain:nil];
    [self setTcpFlood:nil];
    [self setTcpNoReplies:nil];
    [self setTcpPacketDisplay:nil];
    [self setTcpListen:nil];
    [self setTcpListenConn:nil];
    [self setTcpPicker:nil];
    
    [self setUdpView:nil];
    [self setUdpTarget:nil];
    [self setUdpSource:nil];
    [self setUdpPort:nil];
    [self setUdpSrcPort:nil];
    [self setUdpListen:nil];
    [self setUdpAgain:nil];
    [self setUdpFlood:nil];
    [self setUdpPacketDisplay:nil];
    [self setUdpTtlSlider:nil];
    [self setUdpCountSlider:nil];
    [self setUdpSizeSlider:nil];
    [self setUdpThreadsSlider:nil];
    [self setUdpTtl:nil];
    [self setUdpCount:nil];
    [self setUdpSize:nil];
    [self setUdpThreads:nil];
    [self setUdpStart:nil];
    
    [self setArpView:nil];
    [self setArpMacdst:nil];
    [self setArpMacsrc:nil];
    [self setArpTarget:nil];
    [self setArpSource:nil];
    [self setArpListen:nil];
    [self setArpTypeA:nil];
    [self setArpTypeB:nil];
    [self setArpFlood:nil];
    [self setArpAgain:nil];
    [self setArpPacketDisplay:nil];
    [self setArpThreadsSlider:nil];
    [self setArpThreads:nil];
    [self setArpStart:nil];
    [self setArpPicker:nil];
    [self setArpBroadcast:nil];
    [self setArpTargetArping:nil];
    [self setArpThreadsSliderArping:nil];
    [self setArpThreadsArping:nil];
    [self setArpStartArping:nil];
    [self setArpTargetMacflood:nil];
    [self setArpThreadsSliderMacflood:nil];
    [self setArpThreadsMacflood:nil];
    [self setArpStartMacflood:nil];
    [self setArpTargetArpcannon1:nil];
    [self setArpTargetArpcannon2:nil];
    [self setArpThreadsSliderArpcannon:nil];
    [self setArpThreadsArpcannon:nil];
    [self setArpStartArpcannon:nil];
    [self setArpTargetException:nil];
    
    [self setWebView:nil];
    [self setWebTarget:nil];
    [self setWebPort:nil];
    [self setWebHttp:nil];
    [self setWebTcpconn:nil];
    [self setWebTcpsyn:nil];
    [self setWebTcpack:nil];
    [self setWebIcmp:nil];
    [self setWebUdp:nil];
    [self setWebThreadsSlider:nil];
    [self setWebThreads:nil];
    [self setWebStart:nil];
    
    [self setIrcView:nil];
    [self setIrcTarget:nil];
    [self setIrcPort:nil];
    [self setIrcChannel:nil];
    [self setIrcPassword:nil];
    [self setIrcStart:nil];
    [self setIrcStatusView:nil];
    [self setIrcStatusMessage:nil];
    [self setIrcStatusProgress:nil];

    [super viewDidUnload];
}

@end
