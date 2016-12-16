//
//  Libsodium.m
//  selvakumar
//
//  Created by Selvakumar Arunachalam on 03/08/2016.
//
//
#import "Cordova/CDV.h"
#import "Cordova/CDVViewController.h"
#import "Libsodium.h"
#import "sodium.h"
@interface Libsodium ()


@end

@implementation Libsodium


- (void)initKey:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* result = nil;

    unsigned char privateKey[crypto_box_SECRETKEYBYTES];
    unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
    
    crypto_box_keypair(publicKey, privateKey);
    
    NSData *privateKeyData = [NSData dataWithBytes:privateKey length:crypto_box_SECRETKEYBYTES];
    NSData *publicKeyData = [NSData dataWithBytes:publicKey length:crypto_box_PUBLICKEYBYTES];
    
    NSDictionary *json = [NSDictionary dictionaryWithObjectsAndKeys:
                          [privateKeyData base64EncodedStringWithOptions:0], @"pk",
                          [publicKeyData base64EncodedStringWithOptions:0], @"sk",
                          nil];
    NSLog(@"initKey JSON : %@",json);
    result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:json];
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (void)cryptobox_open:(CDVInvokedUrlCommand*)command {
    
    CDVPluginResult* result = nil;
    /* base64 to nsdata conversion */
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:[command.arguments objectAtIndex:0] options:0];
    NSData *pkData = [[NSData alloc] initWithBase64EncodedString:[command.arguments objectAtIndex:1] options:0];
    NSData *nonceData = [[NSData alloc] initWithBase64EncodedString:[command.arguments objectAtIndex:2] options:0];
    NSData *mySkData = [[NSData alloc] initWithBase64EncodedString:[command.arguments objectAtIndex:3] options:0];
    
    
    NSUInteger packedNonceLength = 0;
    NSData *decryptedData = nil;
    NSMutableData *paddedEncryptedData = [NSMutableData dataWithCapacity:cipherData.length + crypto_box_BOXZEROBYTES - packedNonceLength];
    [paddedEncryptedData appendData:[NSMutableData dataWithLength:crypto_box_BOXZEROBYTES]];
    
    NSRange encryptedDataRange = {packedNonceLength, cipherData.length - packedNonceLength};
    [paddedEncryptedData appendData:[cipherData subdataWithRange:encryptedDataRange]];
    
    unsigned char message[paddedEncryptedData.length];
    
    int status = crypto_box_open(message,
                                 paddedEncryptedData.bytes,
                                 paddedEncryptedData.length,
                                 nonceData.bytes,
                                 pkData.bytes,
                                 mySkData.bytes);
    
    if (status != 0) {
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Failed"];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }else{
        decryptedData = [NSData dataWithBytes:message + crypto_box_ZEROBYTES
                                       length:paddedEncryptedData.length - crypto_box_ZEROBYTES];
        NSString* plainText;
        plainText = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
        NSDictionary *json = [NSDictionary dictionaryWithObjectsAndKeys:
                              plainText, @"plainText",
                              nil];
        NSLog(@"decryptNverify JSON : %@",json);
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:json];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }
}


- (void)cryptobox_create:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* result = nil;

    NSString *plainText = [command.arguments objectAtIndex:0];
    NSData* plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *pkData = [[NSData alloc] initWithBase64EncodedString:[command.arguments objectAtIndex:1] options:0];
    NSData *skData = [[NSData alloc] initWithBase64EncodedString:[command.arguments objectAtIndex:2] options:0];
    
    NSMutableData *paddedMessage = [NSMutableData dataWithCapacity:crypto_box_ZEROBYTES + plainData.length];
    [paddedMessage appendData:[NSMutableData dataWithLength:crypto_box_ZEROBYTES]];
    [paddedMessage appendData:plainData];
    
    unsigned char *encryptedDataBuffer = calloc(paddedMessage.length, sizeof(unsigned char));

    NSData *nonceData = [self RandomBytes];
    int status = crypto_box(encryptedDataBuffer,
                            paddedMessage.bytes,
                            paddedMessage.length,
                            nonceData.bytes,
                            pkData.bytes,
                            skData.bytes);
    NSData *encryptedData = nil;
    if (status != 0) {
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Failed"];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    } else {
        NSMutableData *encryptedDataPlusNonce = [NSMutableData data];
        [encryptedDataPlusNonce appendData:nonceData];
        [encryptedDataPlusNonce appendBytes:encryptedDataBuffer + crypto_box_BOXZEROBYTES
                                     length:paddedMessage.length - crypto_box_BOXZEROBYTES];
        encryptedData = [encryptedDataPlusNonce copy];
        
        NSDictionary *json = [NSDictionary dictionaryWithObjectsAndKeys:
                              [[encryptedData subdataWithRange:NSMakeRange([nonceData length], [encryptedData length] - [nonceData length])] base64EncodedStringWithOptions:0], @"ct",
                              [nonceData base64EncodedStringWithOptions:0], @"nonce",
                              nil];
        NSLog(@" encryptNauthenticate JSON : %@",json);
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:json];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }    
}

- (NSData *)RandomBytes{
    NSUInteger nonceLength = crypto_box_NONCEBYTES;
    unsigned char noncebuf[nonceLength];
    randombytes_buf(noncebuf, nonceLength);
    return [NSData dataWithBytes:noncebuf length:nonceLength];
}



@end
