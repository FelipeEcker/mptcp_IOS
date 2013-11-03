//
//  ViewController.h
//  Mptcp
//
//  Created by Felipe Ecker on 09/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "Console.h"
#import "Icmp.h"
#import "Tcp.h"
#import "Udp.h"
#import "Arp.h"
#import "Web.h"
#import "Irc.h"

#define ICMP_VIEW   0
#define TCP_VIEW    1
#define UDP_VIEW    2
#define ARP_VIEW    3
#define WEB_VIEW    4
#define IRC_VIEW    5

@interface ViewController : UIViewController <UIPickerViewDelegate, UIPickerViewDataSource, UITableViewDelegate, UITableViewDataSource> {
    unsigned int screen;
    Console *resultConsole;
    Icmp *icmp;
    Tcp *tcp;
    Udp *udp;
    Arp *arp;
    Web *web;
    Irc *irc;
}

@property (strong, nonatomic) IBOutlet UINavigationBar *navbar;
@property (strong, nonatomic) IBOutlet UISegmentedControl *modesBar;
@property (strong, nonatomic) IBOutlet UIButton *backBtn;
@property (strong, nonatomic) IBOutlet UIButton *infoBtn;
@property (strong, nonatomic) IBOutlet UIScrollView *scroller;
@property (strong, nonatomic) IBOutlet UIView *infoView;
@property (strong, nonatomic) IBOutlet UIView *resultView;
@property (strong, nonatomic) IBOutlet UITableView *console;
@property (strong, nonatomic) IBOutlet UIButton *stopBtn;
@property (strong, nonatomic) IBOutlet UIButton *clearBtn;

@property (strong, nonatomic) IBOutlet UIControl *icmpView;
@property (strong, nonatomic) IBOutlet UITextField *icmpTarget;
@property (strong, nonatomic) IBOutlet UITextField *icmpSource;
@property (strong, nonatomic) IBOutlet UILabel *icmpType;
@property (strong, nonatomic) IBOutlet UIPickerView *icmpPicker;
@property (strong, nonatomic) IBOutlet UISwitch *icmpListen;
@property (strong, nonatomic) IBOutlet UISwitch *icmpAgain;
@property (strong, nonatomic) IBOutlet UISwitch *icmpFlood;
@property (strong, nonatomic) IBOutlet UISwitch *icmpNoReplies;
@property (strong, nonatomic) IBOutlet UISwitch *icmpPacketDisplay;
@property (strong, nonatomic) IBOutlet UISlider *icmpTtlSlider;
@property (strong, nonatomic) IBOutlet UISlider *icmpCountSlider;
@property (strong, nonatomic) IBOutlet UISlider *icmpSizeSlider;
@property (strong, nonatomic) IBOutlet UISlider *icmpThreadsSlider;
@property (strong, nonatomic) IBOutlet UILabel *icmpTtl;
@property (strong, nonatomic) IBOutlet UILabel *icmpCount;
@property (strong, nonatomic) IBOutlet UILabel *icmpSize;
@property (strong, nonatomic) IBOutlet UILabel *icmpThreads;
@property (strong, nonatomic) IBOutlet UIButton *icmpStart;

@property (strong, nonatomic) IBOutlet UIControl *tcpView;
@property (strong, nonatomic) IBOutlet UITextField *tcpTarget;
@property (strong, nonatomic) IBOutlet UITextField *tcpSource;
@property (strong, nonatomic) IBOutlet UITextField *tcpPort;
@property (strong, nonatomic) IBOutlet UITextField *tcpSrcPort;
@property (strong, nonatomic) IBOutlet UILabel *tcpType;
@property (strong, nonatomic) IBOutlet UIPickerView *tcpPicker;
@property (strong, nonatomic) IBOutlet UISwitch *tcpListenConn;
@property (strong, nonatomic) IBOutlet UISwitch *tcpListen;
@property (strong, nonatomic) IBOutlet UISwitch *tcpAgain;
@property (strong, nonatomic) IBOutlet UISwitch *tcpFlood;
@property (strong, nonatomic) IBOutlet UISwitch *tcpNoReplies;
@property (strong, nonatomic) IBOutlet UISwitch *tcpPacketDisplay;
@property (strong, nonatomic) IBOutlet UISlider *tcpTtlSlider;
@property (strong, nonatomic) IBOutlet UISlider *tcpCountSlider;
@property (strong, nonatomic) IBOutlet UISlider *tcpSizeSlider;
@property (strong, nonatomic) IBOutlet UISlider *tcpThreadsSlider;
@property (strong, nonatomic) IBOutlet UILabel *tcpTtl;
@property (strong, nonatomic) IBOutlet UILabel *tcpCount;
@property (strong, nonatomic) IBOutlet UILabel *tcpSize;
@property (strong, nonatomic) IBOutlet UILabel *tcpThreads;
@property (strong, nonatomic) IBOutlet UIButton *tcpStart;

@property (strong, nonatomic) IBOutlet UIControl *udpView;
@property (strong, nonatomic) IBOutlet UITextField *udpTarget;
@property (strong, nonatomic) IBOutlet UITextField *udpSource;
@property (strong, nonatomic) IBOutlet UITextField *udpPort;
@property (strong, nonatomic) IBOutlet UITextField *udpSrcPort;
@property (strong, nonatomic) IBOutlet UISwitch *udpListen;
@property (strong, nonatomic) IBOutlet UISwitch *udpAgain;
@property (strong, nonatomic) IBOutlet UISwitch *udpFlood;
@property (strong, nonatomic) IBOutlet UISwitch *udpPacketDisplay;
@property (strong, nonatomic) IBOutlet UISlider *udpTtlSlider;
@property (strong, nonatomic) IBOutlet UISlider *udpCountSlider;
@property (strong, nonatomic) IBOutlet UISlider *udpSizeSlider;
@property (strong, nonatomic) IBOutlet UISlider *udpThreadsSlider;
@property (strong, nonatomic) IBOutlet UILabel *udpTtl;
@property (strong, nonatomic) IBOutlet UILabel *udpCount;
@property (strong, nonatomic) IBOutlet UILabel *udpSize;
@property (strong, nonatomic) IBOutlet UILabel *udpThreads;
@property (strong, nonatomic) IBOutlet UIButton *udpStart;

@property (strong, nonatomic) IBOutlet UIControl *arpView;
@property (strong, nonatomic) IBOutlet UITextField *arpMacdst;
@property (strong, nonatomic) IBOutlet UITextField *arpMacsrc;
@property (strong, nonatomic) IBOutlet UITextField *arpTarget;
@property (strong, nonatomic) IBOutlet UITextField *arpSource;
@property (strong, nonatomic) IBOutlet UISwitch *arpListen;
@property (strong, nonatomic) IBOutlet UILabel *arpTypeA;
@property (strong, nonatomic) IBOutlet UILabel *arpTypeB;
@property (strong, nonatomic) IBOutlet UIPickerView *arpPicker;
@property (strong, nonatomic) IBOutlet UISwitch *arpFlood;
@property (strong, nonatomic) IBOutlet UISwitch *arpAgain;
@property (strong, nonatomic) IBOutlet UISwitch *arpPacketDisplay;
@property (strong, nonatomic) IBOutlet UISlider *arpThreadsSlider;
@property (strong, nonatomic) IBOutlet UILabel *arpThreads;
@property (strong, nonatomic) IBOutlet UIButton *arpStart;
@property (strong, nonatomic) IBOutlet UIButton *arpBroadcast;
@property (strong, nonatomic) IBOutlet UITextField *arpTargetArping;
@property (strong, nonatomic) IBOutlet UISlider *arpThreadsSliderArping;
@property (strong, nonatomic) IBOutlet UILabel *arpThreadsArping;
@property (strong, nonatomic) IBOutlet UIButton *arpStartArping;
@property (strong, nonatomic) IBOutlet UITextField *arpTargetMacflood;
@property (strong, nonatomic) IBOutlet UISlider *arpThreadsSliderMacflood;
@property (strong, nonatomic) IBOutlet UILabel *arpThreadsMacflood;
@property (strong, nonatomic) IBOutlet UIButton *arpStartMacflood;
@property (strong, nonatomic) IBOutlet UITextField *arpTargetArpcannon1;
@property (strong, nonatomic) IBOutlet UITextField *arpTargetArpcannon2;
@property (strong, nonatomic) IBOutlet UITextField *arpTargetException;
@property (strong, nonatomic) IBOutlet UISlider *arpThreadsSliderArpcannon;
@property (strong, nonatomic) IBOutlet UILabel *arpThreadsArpcannon;
@property (strong, nonatomic) IBOutlet UIButton *arpStartArpcannon;

@property (strong, nonatomic) IBOutlet UIControl *webView;
@property (strong, nonatomic) IBOutlet UITextField *webTarget;
@property (strong, nonatomic) IBOutlet UITextField *webPort;
@property (strong, nonatomic) IBOutlet UISwitch *webHttp;
@property (strong, nonatomic) IBOutlet UISwitch *webTcpconn;
@property (strong, nonatomic) IBOutlet UISwitch *webTcpsyn;
@property (strong, nonatomic) IBOutlet UISwitch *webTcpack;
@property (strong, nonatomic) IBOutlet UISwitch *webIcmp;
@property (strong, nonatomic) IBOutlet UISwitch *webUdp;
@property (strong, nonatomic) IBOutlet UISlider *webThreadsSlider;
@property (strong, nonatomic) IBOutlet UILabel *webThreads;
@property (strong, nonatomic) IBOutlet UIButton *webStart;

@property (strong, nonatomic) IBOutlet UIControl *ircView;
@property (strong, nonatomic) IBOutlet UITextField *ircTarget;
@property (strong, nonatomic) IBOutlet UITextField *ircPort;
@property (strong, nonatomic) IBOutlet UITextField *ircChannel;
@property (strong, nonatomic) IBOutlet UITextField *ircPassword;
@property (strong, nonatomic) IBOutlet UIButton *ircStart;
@property (strong, nonatomic) IBOutlet UIView *ircStatusView;
@property (strong, nonatomic) IBOutlet UILabel *ircStatusMessage;
@property (strong, nonatomic) IBOutlet UIProgressView *ircStatusProgress;

@end
