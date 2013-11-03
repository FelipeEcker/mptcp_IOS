//
//  Web.h
//  Mptcptmp
//
//  Created by Felipe Ecker on 10/07/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

#import "Core.h"
#import "Console.h"

@interface Web : NSObject

@property UITextField *target;
@property UITextField *port;
@property UISwitch *http;
@property UISwitch *tcpconn;
@property UISwitch *tcpsyn;
@property UISwitch *tcpack;
@property UISwitch *icmp;
@property UISwitch *udp;
@property UISlider *threadsSlider;
@property UILabel *threadsLabel;
@property NSMutableArray *threads;
@property UIButton *start;
@property NSTimer *check;
@property BOOL stop;

- (void)ReturnKeyboard;
- (void)editChanged;
- (void)changeThreads;
- (void)changeStates;
- (void)run;
- (void)doStop;

@end
