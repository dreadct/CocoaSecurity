//
//  CocoaSecurityDecoder.m
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

#import "CocoaSecurityDecoder.h"

#import "Constants.h"


@implementation CocoaSecurityDecoder

//MARK: - Singleton

+ (instancetype _Nonnull)sharedDecoder {
    static CocoaSecurityDecoder *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}


//MARK: - Public methods

- (NSData * _Nullable)base64:(NSString * _Nonnull)string {
    if (string.length == 0) {
        return nil;
    }
    return [[NSData alloc] initWithBase64EncodedString:string options:0];
}

- (NSData * _Nullable)hex:(NSString * _Nonnull)data {
    if (data.length == 0) {
        return nil;
    }

    static const unsigned char HexDecodeChars[] =
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, //49
        2, 3, 4, 5, 6, 7, 8, 9, 0, 0, //59
        0, 0, 0, 0, 0, 10, 11, 12, 13, 14,
        15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  //79
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 10, 11, 12,   //99
        13, 14, 15
    };

    // convert data(NSString) to CString
    const char *source = [data cStringUsingEncoding:NSUTF8StringEncoding];
    // malloc buffer
    unsigned char *buffer;
    NSUInteger length = strlen(source) / 2;
    buffer = malloc(length);
    for (NSUInteger index = 0; index < length; index++) {
        buffer[index] = (HexDecodeChars[source[index * 2]] << 4) + (HexDecodeChars[source[index * 2 + 1]]);
    }
    // init result NSData
    NSData *result = [NSData dataWithBytes:buffer length:length];
    free(buffer);
    source = nil;

    return  result;
}

@end
