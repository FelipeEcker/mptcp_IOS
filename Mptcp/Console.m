//
//  Console.m
//  Mptcptmp
//
//  Created by Felipe Ecker on 20/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import "Console.h"
#import <QuartzCore/QuartzCore.h>

static unsigned int consoleRow = 0;
extern UITableView *console;

@implementation Console

+ (void) roll:(NSString *)msg forInit:(bool)init toTittle:(bool)tittle inDump:(bool)dump {

    register unsigned int it, jt = 0, input = [msg length] + 1;
    char __mem[input];
    memset(__mem, 0, input);
    
    for (it = 0; it < (input - 1); it++) {
        if ( ([msg characterAtIndex:it] == '\n') || (jt == 54)) {
    
            [Console __roll:[NSString stringWithFormat:@"%s", __mem] forInit:init toTittle:tittle inDump:dump];
            
            [CATransaction flush];
            memset(__mem, 0, jt);
            
            jt = 0;
            if([msg characterAtIndex:it] == '\n') continue;
        }
        __mem[jt++] = [msg characterAtIndex:it];
    }
    
    [Console __roll:[NSString stringWithFormat:@"%s", __mem] forInit:init toTittle:tittle inDump:dump];
    [CATransaction flush];
}

+ (void) __roll:(NSString *) msg forInit:(bool) init toTittle:(bool)tittle inDump:(bool)dump {
    
    NSIndexPath *row, *row_next;
    UITableViewCell *cell, *cell_next;
    
    if (init) {
        consoleRow = 0;
        for (int it = 0; it < 16; it++){
            row = [NSIndexPath indexPathForRow:it inSection:0];
            cell = [console cellForRowAtIndexPath:row];
            cell.textLabel.textColor = [UIColor blackColor];
            cell.textLabel.font = [UIFont fontWithName:@"Verdana" size:14.0];
            cell.textLabel.text = @"NoneNoneNoneNoneNoneNoneNone";
        }
    }

    if (consoleRow > 15) {
        for (int it = 0; it < 16; it++) {
            row = [NSIndexPath indexPathForRow:it inSection:0];
            cell = [console cellForRowAtIndexPath:row];
            if (tittle && dump) {
                cell.textLabel.textColor = [UIColor cyanColor];
                cell.textLabel.font = [UIFont fontWithName:@"Verdana" size:14.0];
            } else if (tittle) {
                cell.textLabel.textColor = [UIColor whiteColor];
                cell.textLabel.font = [UIFont fontWithName:@"Helvetica" size:15.0];
            } else if (dump) {
                cell.textLabel.textColor = [UIColor cyanColor];
                cell.textLabel.font = [UIFont fontWithName:@"Courier" size:12.0];
            } else {
                cell.textLabel.textColor = [UIColor lightGrayColor];
                cell.textLabel.font = [UIFont fontWithName:@"Verdana" size:14.0];
            }

            if (it == 15) {
                cell.textLabel.text = msg;
                break;
            }
            row_next = [NSIndexPath indexPathForRow:it+1 inSection:0];
            cell_next = [console cellForRowAtIndexPath:row_next];
            cell.textLabel.textColor = cell_next.textLabel.textColor;
            cell.textLabel.font = cell_next.textLabel.font;
            cell.textLabel.text = cell_next.textLabel.text;
        }
    } else {
        row = [NSIndexPath indexPathForRow:consoleRow inSection:0];
        cell = [console cellForRowAtIndexPath:row];
        if (tittle && dump) {
            cell.textLabel.textColor = [UIColor cyanColor];
            cell.textLabel.font = [UIFont fontWithName:@"Verdana" size:14.0];
        } else if (tittle) {
            cell.textLabel.textColor = [UIColor whiteColor];
            cell.textLabel.font = [UIFont fontWithName:@"Helvetica" size:15.0];
        } else if (dump) {
            cell.textLabel.textColor = [UIColor cyanColor];
            cell.textLabel.font = [UIFont fontWithName:@"Courier" size:12.0];
        } else {
            cell.textLabel.textColor = [UIColor lightGrayColor];
            cell.textLabel.font = [UIFont fontWithName:@"Verdana" size:14.0];
        }
        
        cell.textLabel.text = msg;
    }
    
    consoleRow++;
}

@end
