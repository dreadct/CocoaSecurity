//
//  CocoaSecurityEncoder.h
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

@import Foundation;

@interface CocoaSecurityEncoder : NSObject

//MARK: - Singleton

+ (instancetype _Nonnull)sharedEncoder;


//MARK: - Methods

- (NSString * _Nullable)base64:(NSData * _Nonnull)data;

- (NSString * _Nullable)hex:(NSData * _Nonnull)data
                   useLower:(BOOL)isOutputLower;

@end
