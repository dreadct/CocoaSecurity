//
//  CocoaSecurityResult.m
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

#import "CocoaSecurityResult.h"

#import "CocoaSecurityEncoder.h"

@implementation CocoaSecurityResult

@synthesize data = _data;

//MARK: - Initializers

- (instancetype _Nonnull)initWithBytes:(unsigned char[_Nonnull])initData
                                length:(NSUInteger)length {
    self = [super init];
    if (self) {
        _data = [NSData dataWithBytes:initData length:length];
    }
    return self;
}


//MARK: - Properties

- (NSString * _Nullable)base64 {
    return [[CocoaSecurityEncoder sharedEncoder] base64:self.data];
}

- (NSString *)hex {
    return [[CocoaSecurityEncoder sharedEncoder] hex:self.data useLower:false];
}

- (NSString *)hexLower {
    return [[CocoaSecurityEncoder sharedEncoder] hex:self.data useLower:true];
}

- (NSString * _Nullable)utf8String {
    NSString *result = [[NSString alloc] initWithData:self.data
                                             encoding:NSUTF8StringEncoding];
    return result;
}

@end
