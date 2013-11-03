//
//  main.m
//  Mptcp
//
//  Created by Felipe Ecker on 09/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

UITableView *console;

int main(int argc, char *argv[]) {
    sleep(3);
    setuid(0);
    setgid(0);
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
