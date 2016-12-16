//
//  Libsodium.h
//  selvakumar
//
//  Created by Selvakumar Arunachalam on 03/08/2016.
//
//

#import <Cordova/CDVPlugin.h>




@interface Libsodium : CDVPlugin
- (void)initKey:(CDVInvokedUrlCommand*)command;
- (void)cryptobox_open:(CDVInvokedUrlCommand*)command;
- (void)cryptobox_create:(CDVInvokedUrlCommand*)command;

@end