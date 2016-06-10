//
//  HttpSSLTest.m
//  CustomPlugin
//
//  Created by Admin on 07.06.16.
//
//

#import "HttpSSL.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>

@interface CustomURLConnectionDelegate : NSObject <NSURLConnectionDelegate>

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property  NSString *_pathKey;
@property NSString *_password;


- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId pathKey:(NSString*)pathKey password:(NSString*)password;
@end

@implementation CustomURLConnectionDelegate

@synthesize _pathKey, _password;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId pathKey:(NSString*)pathKey password:(NSString*)password
{
    self._plugin = plugin;
    self._callbackId = callbackId;
    self._pathKey = pathKey;
    self._password = password;
    
    return self;
}
- (void)connection:(NSURLConnection *) connection didReceiveResponse:(NSURLResponse *)response
{
    NSLog(@"Response recieved");
}

- (void)connection:(NSURLConnection*) connection didReceiveData:(NSData *)data
{
    NSLog(@"Data recieved");
    
    NSString *responseString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:responseString];
    [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSLog(@"Authentication challenge");
    
    // load cert
    NSString *path = [[NSBundle mainBundle] pathForResource:self._pathKey ofType:@"p12"];
    NSData *p12data = [NSData dataWithContentsOfFile:path];
    CFDataRef inP12data = (__bridge CFDataRef)p12data;
    
    
    SecIdentityRef myIdentity;
    SecTrustRef myTrust;
    
    
    OSStatus status = extractIdentityAndTrust(inP12data, &myIdentity, &myTrust, self._password);
    
    SecCertificateRef myCertificate;
    SecIdentityCopyCertificate(myIdentity, &myCertificate);
    const void *certs[] = { myCertificate };
    CFArrayRef certsArray = CFArrayCreate(NULL, certs, 1, NULL);
    
    NSURLCredential *credential = [NSURLCredential credentialWithIdentity:myIdentity certificates:(__bridge NSArray*)certsArray persistence:NSURLCredentialPersistencePermanent];
    
    [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
}

- (void)connection:(NSURLConnection*) connection didFailWithError:(NSError *)error
{
    connection = nil;
    
    NSString *resultCode = @"CONNECTION_FAILED. Details:";
    NSString *errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:errStr];
    [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    return YES;
}


OSStatus extractIdentityAndTrust(CFDataRef inP12data, SecIdentityRef *identity, SecTrustRef *trust, NSString *pass)
{
    OSStatus securityError = errSecSuccess;
    
    CFStringRef password = (__bridge CFStringRef)pass;
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12data, options, &items);
    
    if (securityError == 0) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
        *trust = (SecTrustRef)tempTrust;
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityError;
}
@end

@interface HttpSSL ()

@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSMutableData *_connections;

@end

@implementation HttpSSL

- (void) cordovaHttpSSL:(CDVInvokedUrlCommand *)command {
    
    NSString *serverURL = [command.arguments objectAtIndex:0];
    NSString *pathKeyTemp = [command.arguments objectAtIndex:1];
    NSString *passwordTemp = [command.arguments objectAtIndex:2];

   
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL]cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:60.0];
    
    CustomURLConnectionDelegate *delegate =[[CustomURLConnectionDelegate alloc] initWithPlugin:self
                                                                                 callbackId:command.callbackId
                                                                                       pathKey:pathKeyTemp
                                                                                      password:passwordTemp];
    
    
    
    if (![NSURLConnection connectionWithRequest:request delegate:delegate]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_FAILED"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}


@end

