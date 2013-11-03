//
//  Irc.h
//  Mptcptmp
//
//  Created by Felipe Ecker on 12/07/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

#import "Core.h"

@interface Irc : NSObject

@property UITextField *target;
@property UITextField *port;
@property UITextField *channel;
@property UITextField *password;
@property UIButton *start;
@property NSTimer *check;
@property UIProgressView *statusProgress;
@property UILabel *statusMessage;
@property BOOL stop;
@property BOOL running;

- (void)ReturnKeyboard;
- (void)editChanged;
- (void)run;
- (void)doStop;

@end
