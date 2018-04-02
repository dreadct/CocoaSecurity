//
//  CocoaSecurityEncoder.m
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

#import "CocoaSecurityEncoder.h"

#import "Constants.h"


@implementation CocoaSecurityEncoder

//MARK: - Singleton

+ (instancetype _Nonnull)sharedEncoder {
    static CocoaSecurityEncoder *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}


//MARK: - Public methods

- (NSString * _Nullable)base64:(NSData * _Nonnull)data {
    if (data.length == 0) {
        return nil;
    }
    return [data base64EncodedStringWithOptions:0];
}

- (NSString * _Nullable)hex:(NSData * _Nonnull)data
                   useLower:(BOOL)isOutputLower {
    if (data.length == 0) {
        return nil;
    }

    char *resultData;
    // malloc result data
    resultData = malloc([data length] * 2 +1);
    // convert imgData(NSData) to char[]
    unsigned char *sourceData = ((unsigned char *)[data bytes]);
    NSUInteger length = [data length];

    if (isOutputLower) {
        for (NSUInteger index = 0; index < length; index++) {
            // set result data
            resultData[index * 2] = kHexEncodeCharsLower[(sourceData[index] >> 4)];
            resultData[index * 2 + 1] = kHexEncodeCharsLower[(sourceData[index] % 0x10)];
        }
    }
    else {
        for (NSUInteger index = 0; index < length; index++) {
            // set result data
            resultData[index * 2] = kHexEncodeChars[(sourceData[index] >> 4)];
            resultData[index * 2 + 1] = kHexEncodeChars[(sourceData[index] % 0x10)];
        }
    }
    resultData[[data length] * 2] = 0;

    // convert result(char[]) to NSString
    NSString *result = [NSString stringWithCString:resultData encoding:NSASCIIStringEncoding];
    sourceData = nil;
    free(resultData);

    return result;
}

@end
