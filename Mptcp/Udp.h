//
//  Udp.h
//  Mptcptmp
//
//  Created by Felipe Ecker on 02/07/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

#import "Core.h"
#import "Console.h"

@interface Udp : NSObject {
    uint __count;
}

@property UITextField *target;
@property UITextField *source;
@property UITextField *port;
@property UITextField *srcPort;
@property UISwitch *listen;
@property UISwitch *again;
@property UISwitch *flood;
@property UISwitch *packetDisplay;
@property UISlider *ttlSlider;
@property UISlider *countSlider;
@property UISlider *sizeSlider;
@property UISlider *threadsSlider;
@property UILabel *ttl;
@property UILabel *count;
@property UILabel *size;
@property UILabel *threadsLabel;
@property UIButton *start;
@property NSMutableArray *threads;
@property NSTimer *check;
@property BOOL stop;

- (void)ReturnKeyboard;
- (void)editChanged;
- (void)changeTtl;
- (void)changeCount;
- (void)changeSize;
- (void)changeThreads;
- (void)changeStates;
- (void)run;
- (void)doStop;

@end
