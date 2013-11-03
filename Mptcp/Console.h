//
//  Console.h
//  Mptcptmp
//
//  Created by Felipe Ecker on 20/06/13.
//  Copyright (c) 2013 Felipe Ecker. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Console : NSObject

+(void) roll:(NSString *) msg forInit:(bool) init toTittle:(bool) tittle inDump:(bool) dump;
+(void) __roll:(NSString *) msg forInit:(bool) init toTittle:(bool) tittle inDump:(bool) dump;

@end
