//
//  Tcp.h
//  Mptcptmp
//
//  Created by Felipe Ecker on 25/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

#import "Core.h"
#import "Console.h"

#define BIGBUFF 10240

@interface Tcp : NSObject {
    uint __count;
}

@property unsigned int pickerNumberComponents;
@property unsigned int pickerNumberRows;
@property NSArray *types;
@property UITextField *target;
@property UITextField *source;
@property UITextField *port;
@property UITextField *srcPort;
@property UILabel *type;
@property UIPickerView *picker;
@property UISwitch *listenConn;
@property UISwitch *listen;
@property UISwitch *again;
@property UISwitch *flood;
@property UISwitch *noReplies;
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
- (NSString *)pickerTitle:(NSInteger) row;
- (void)pickerSelectedRow:(NSInteger) row;
- (void)run;
- (void)doStop;

@end
