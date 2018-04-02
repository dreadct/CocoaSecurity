//
//  CocoaSecurityResult.h
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

@import Foundation;

@interface CocoaSecurityResult : NSObject

//MARK: - Properties

@property (strong, nonatomic, readonly) NSData * _Nonnull data;
@property (strong, nonatomic, readonly) NSString * _Nullable base64;
@property (strong, nonatomic, readonly) NSString * _Nullable hex;
@property (strong, nonatomic, readonly) NSString * _Nullable hexLower;
@property (strong, nonatomic, readonly) NSString * _Nullable utf8String;


//MARK: - Initilizers

- (instancetype _Nonnull)initWithBytes:(unsigned char[_Nonnull])initData
                                length:(NSUInteger)length;

@end
