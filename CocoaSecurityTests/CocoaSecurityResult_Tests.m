//
//  CocoaSecurityResult_Tests_.m
//  CocoaSecurityTests
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

@import XCTest;
@import CocoaSecurity;


@interface CocoaSecurityResult_Tests : XCTestCase

@property (nonatomic, readonly) unsigned char *data;
@property (nonatomic, strong, readonly)  CocoaSecurityResult * _Nonnull result;

@end


@implementation CocoaSecurityResult_Tests

- (void)setUp {
    [super setUp];

    unsigned char data[] =
    {
        0xcd, 0x3d, 0x4f, 0x4b, 0xae, 0x0c, 0x9d, 0x72,
        0x14, 0x0c, 0x25, 0x22, 0xcb, 0x5d, 0xd1, 0x46
    };
    _data = malloc(16);
    memcpy(_data, data, 16);
    _result = [[CocoaSecurityResult alloc] initWithBytes:self.data length:16];
}

- (void)tearDown {
    free(_data);
    [super tearDown];
}

- (void)testBase64 {
    NSString *expected = @"zT1PS64MnXIUDCUiy13RRg==";
    NSString *actual = self.result.base64;
    XCTAssertEqualObjects(expected, actual, @"");
}

- (void)testHex {
    NSString *expected = @"CD3D4F4BAE0C9D72140C2522CB5DD146";
    NSString *actual = self.result.hex;
    XCTAssertEqualObjects(expected, actual, @"");
}

- (void)testHexLower {
    NSString *expected = @"cd3d4f4bae0c9d72140c2522cb5dd146";
    NSString *actual = self.result.hexLower;
    XCTAssertEqualObjects(expected, actual, @"");
}

- (void)testData {
    NSData *expected = [NSData dataWithBytes:self.data length:16];
    NSData *actual = self.result.data;
    XCTAssertEqualObjects(expected, actual, @"");
}

@end
