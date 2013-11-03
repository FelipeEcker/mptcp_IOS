//
//  Icmp.h
//  Mptcp
//
//  Created by Felipe Ecker on 14/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

#import "Core.h"
#import "Console.h"

@interface Icmp : NSObject {
    uint __count;
}

@property unsigned int pickerNumberComponents;
@property unsigned int pickerNumberRows;
@property NSArray *types;
@property UITextField *target;
@property UITextField *source;
@property UILabel *type;
@property UIPickerView *picker;
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
