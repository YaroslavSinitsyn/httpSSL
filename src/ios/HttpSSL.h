//
//  HttpSSLTest.h
//  CustomPlugin
//
//  Created by Admin on 07.06.16.
//
//

#import <Cordova/CDV.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>

@interface HttpSSL : CDVPlugin

-(void)cordovaHttpSSL:(CDVInvokedUrlCommand *)command;

@end
