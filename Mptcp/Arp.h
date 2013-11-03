//
//  Arp.h
//  Mptcptmp
//
//  Created by Felipe Ecker on 03/07/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

#import "Core.h"
#import "Console.h"

struct __ethdr {
    ethaddr macdst;     /* 6 bytes [00-05]  */
    ethaddr macsrc;     /* 6 bytes [06-11]  */
    uint16 proto;       /* 2 bytes [12-13]  */
    uint16 unused0;     /* 2 bytes [14-15]  */
    uint16 unused1;     /* 2 bytes [16-17]  */
    uint16 unused2;     /* 2 bytes [18-19]  */
    uint16 type;        /* 2 bytes [20-21]  */
    ethaddr msrc;       /* 6 bytes [22-27]  */
    uint32 ipsrc;       /* 4 bytes [28-31]  */
    ethaddr mdst;       /* 6 bytes [32-37]  */
    uint32 ipdst;       /* 4 bytes [38-41]  */
    
} __packed__;          /* Packing 42 bytes */

@interface Arp : NSObject {
    uint __count;
}

@property unsigned int pickerNumberComponents;
@property unsigned int pickerNumberRows;
@property NSArray *typesA;
@property NSArray *typesB;
@property UILabel *typeA;
@property UILabel *typeB;
@property UITextField *target;
@property UITextField *source;
@property UITextField *macdst;
@property UITextField *macsrc;
@property UISwitch *listen;
@property UIPickerView *picker;
@property UISwitch *again;
@property UISwitch *flood;
@property UISwitch *packetDisplay;
@property UISlider *threadsSlider;
@property UILabel *threadsLabel;
@property UIButton *broadcast;
@property UIButton *start;
@property NSMutableArray *threads;
@property UITextField *targetArping;
@property UISlider *threadsSliderArping;
@property UILabel *threadsArping;
@property UIButton *startArping;
@property UITextField *targetMacflood;
@property UISlider *threadsSliderMacflood;
@property UILabel *threadsMacflood;
@property UIButton *startMacflood;
@property UITextField *targetArpcannon1;
@property UITextField *targetArpcannon2;
@property UITextField *targetException;
@property UISlider *threadsSliderArpcannon;
@property UILabel *threadsArpcannon;
@property UIButton *startArpcannon;
@property NSTimer *check;
@property BOOL stop;

- (void)ReturnKeyboard;
- (void)editChanged;
- (void)changeThreads;
- (void)changeStates;
- (NSString *)pickerTitle:(NSInteger) row inComponent:(NSInteger) component;
- (void)pickerSelectedRow:(NSInteger) row inComponent:(NSInteger) component;
- (void)setBroadcast;
- (void)changeThreadsArping;
- (void)changeThreadsMacflood;
- (void)changeThreadsArpcannon;
- (void)run:(unsigned int) mode;
- (void)doStop;

@end
