//
//  CocoaSecurityDecoder.h
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

@import Foundation;

@interface CocoaSecurityDecoder : NSObject

//MARK: - Singleton

+ (instancetype _Nonnull)sharedDecoder;


//MARK: - Methods

- (NSData * _Nullable)base64:(NSString * _Nonnull)string;
- (NSData * _Nullable)hex:(NSString * _Nonnull)data;

@end
