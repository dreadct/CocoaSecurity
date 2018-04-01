//
//  CocoaSecurityClass.m
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>

#import "CocoaSecurityClass.h"

#import "CocoaSecurityDecoder.h"
#import "CocoaSecurityResult.h"


@implementation CocoaSecurity

//MARK: - AES Encrypt

// default AES Encrypt, key -> SHA384(key).sub(0, 32), iv -> SHA384(key).sub(32, 16)
+ (CocoaSecurityResult * _Nonnull)aesEncrypt:(NSString * _Nonnull)data key:(NSString * _Nonnull)key {
    CocoaSecurityResult *sha = [self sha384:key];
    NSData *aesKey = [sha.data subdataWithRange:NSMakeRange(0, 32)];
    NSData *aesIv = [sha.data subdataWithRange:NSMakeRange(32, 16)];

    return [self aesEncrypt:data key:aesKey iv:aesIv];
}

//MARK: AES Encrypt 128, 192, 256

+ (CocoaSecurityResult * _Nonnull)aesEncrypt:(NSString * _Nonnull)data hexKey:(NSString * _Nonnull)key hexIv:(NSString * _Nonnull)iv {
    CocoaSecurityDecoder *decoder = [CocoaSecurityDecoder new];
    NSData *aesKey = [decoder hex:key];
    NSData *aesIv = [decoder hex:iv];

    return [self aesEncrypt:data key:aesKey iv:aesIv];
}

+ (CocoaSecurityResult * _Nonnull)aesEncrypt:(NSString * _Nonnull)data key:(NSData * _Nonnull)key iv:(NSData * _Nonnull)iv {
    return [self aesEncryptWithData:[data dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv];
}

+ (CocoaSecurityResult * _Nonnull)aesEncryptWithData:(NSData * _Nonnull)data key:(NSData * _Nonnull)key iv:(NSData * _Nonnull)iv {
    // check length of key and iv
    if ([iv length] != 16) {
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Length of iv is wrong. Length of iv should be 16(128bits)"
                                     userInfo:nil];
    }
    if ([key length] != 16 && [key length] != 24 && [key length] != 32 ) {
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Length of key is wrong. Length of iv should be 16, 24 or 32(128, 192 or 256bits)"
                                     userInfo:nil];
    }

    // setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    // do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          [key bytes],     // Key
                                          [key length],    // kCCKeySizeAES
                                          [iv bytes],       // IV
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:buffer length:encryptedSize];
        free(buffer);

        return result;
    }
    else {
        free(buffer);
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Encrypt Error!"
                                     userInfo:nil];
        return nil;
    }
}

//MARK: - AES Decrypt

// default AES Decrypt, key -> SHA384(key).sub(0, 32), iv -> SHA384(key).sub(32, 16)
+ (CocoaSecurityResult * _Nonnull)aesDecryptWithBase64:(NSString * _Nonnull)data key:(NSString * _Nonnull)key {
    CocoaSecurityResult *sha = [self sha384:key];
    NSData *aesKey = [sha.data subdataWithRange:NSMakeRange(0, 32)];
    NSData *aesIv = [sha.data subdataWithRange:NSMakeRange(32, 16)];

    return [self aesDecryptWithBase64:data key:aesKey iv:aesIv];
}

//MARK: AES Decrypt 128, 192, 256

+ (CocoaSecurityResult * _Nonnull)aesDecryptWithBase64:(NSString * _Nonnull)data hexKey:(NSString * _Nonnull)key hexIv:(NSString * _Nonnull)iv {
    CocoaSecurityDecoder *decoder = [CocoaSecurityDecoder new];
    NSData *aesKey = [decoder hex:key];
    NSData *aesIv = [decoder hex:iv];

    return [self aesDecryptWithBase64:data key:aesKey iv:aesIv];
}

+ (CocoaSecurityResult * _Nonnull)aesDecryptWithBase64:(NSString * _Nonnull)data key:(NSData * _Nonnull)key iv:(NSData * _Nonnull)iv {
    CocoaSecurityDecoder *decoder = [CocoaSecurityDecoder new];
    return [self aesDecryptWithData:[decoder base64:data] key:key iv:iv];
}

+ (CocoaSecurityResult * _Nonnull)aesDecryptWithData:(NSData * _Nonnull)data key:(NSData * _Nonnull)key iv:(NSData * _Nonnull)iv {
    // check length of key and iv
    if ([iv length] != 16) {
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Length of iv is wrong. Length of iv should be 16(128bits)"
                                     userInfo:nil];
    }
    if ([key length] != 16 && [key length] != 24 && [key length] != 32 ) {
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Length of key is wrong. Length of iv should be 16, 24 or 32(128, 192 or 256bits)"
                                     userInfo:nil];
    }

    // setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    // do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          [key bytes],     // Key
                                          [key length],    // kCCKeySizeAES
                                          [iv bytes],       // IV
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:buffer length:encryptedSize];
        free(buffer);

        return result;
    }
    else {
        free(buffer);
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Decrypt Error!"
                                     userInfo:nil];
        return nil;
    }
}


//MARK: - MD5

+ (CocoaSecurityResult * _Nonnull)md5:(NSString * _Nonnull)hashString {
    return [self md5WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (CocoaSecurityResult * _Nonnull)md5WithData:(NSData * _Nonnull)hashData {
    unsigned char *digest;
    digest = malloc(CC_MD5_DIGEST_LENGTH);

    CC_MD5([hashData bytes], (CC_LONG)[hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_MD5_DIGEST_LENGTH];
    free(digest);

    return result;
}


//MARK: - HMAC-MD5

+ (CocoaSecurityResult * _Nonnull)hmacMd5:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key {
    return [self hmacMd5WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding] hmacKey:key];
}

+ (CocoaSecurityResult * _Nonnull)hmacMd5WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key {
    unsigned char *digest;
    digest = malloc(CC_MD5_DIGEST_LENGTH);
    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];

    CCHmac(kCCHmacAlgMD5, cKey, strlen(cKey), [hashData bytes], [hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_MD5_DIGEST_LENGTH];
    free(digest);
    cKey = nil;

    return result;
}


//MARK: - SHA1

+ (CocoaSecurityResult * _Nonnull)sha1:(NSString * _Nonnull)hashString {
    return [self sha1WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (CocoaSecurityResult * _Nonnull)sha1WithData:(NSData * _Nonnull)hashData {
    unsigned char *digest;
    digest = malloc(CC_SHA1_DIGEST_LENGTH);

    CC_SHA1([hashData bytes], (CC_LONG)[hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    free(digest);

    return result;
}

//MARK: SHA224

+ (CocoaSecurityResult * _Nonnull)sha224:(NSString * _Nonnull)hashString {
    return [self sha224WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (CocoaSecurityResult * _Nonnull)sha224WithData:(NSData * _Nonnull)hashData {
    unsigned char *digest;
    digest = malloc(CC_SHA224_DIGEST_LENGTH);

    CC_SHA224([hashData bytes], (CC_LONG)[hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA224_DIGEST_LENGTH];
    free(digest);

    return result;
}

//MARK: SHA256

+ (CocoaSecurityResult * _Nonnull)sha256:(NSString * _Nonnull)hashString {
    return [self sha256WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (CocoaSecurityResult * _Nonnull)sha256WithData:(NSData * _Nonnull)hashData {
    unsigned char *digest;
    digest = malloc(CC_SHA256_DIGEST_LENGTH);

    CC_SHA256([hashData bytes], (CC_LONG)[hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    free(digest);

    return result;
}

//MARK: SHA384

+ (CocoaSecurityResult * _Nonnull)sha384:(NSString * _Nonnull)hashString {
    return [self sha384WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (CocoaSecurityResult * _Nonnull)sha384WithData:(NSData * _Nonnull)hashData {
    unsigned char *digest;
    digest = malloc(CC_SHA384_DIGEST_LENGTH);

    CC_SHA384([hashData bytes], (CC_LONG)[hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA384_DIGEST_LENGTH];
    free(digest);

    return result;
}

//MARK: SHA512

+ (CocoaSecurityResult * _Nonnull)sha512:(NSString * _Nonnull)hashString {
    return [self sha512WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (CocoaSecurityResult * _Nonnull)sha512WithData:(NSData * _Nonnull)hashData {
    unsigned char *digest;
    digest = malloc(CC_SHA512_DIGEST_LENGTH);

    CC_SHA512([hashData bytes], (CC_LONG)[hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
    free(digest);

    return result;
}


//MARK: - HMAC-SHA1

+ (CocoaSecurityResult * _Nonnull)hmacSha1:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key {
    return [self hmacSha1WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding] hmacKey:key];
}

+ (CocoaSecurityResult * _Nonnull)hmacSha1WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key {
    unsigned char *digest;
    digest = malloc(CC_SHA1_DIGEST_LENGTH);
    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];

    CCHmac(kCCHmacAlgSHA1, cKey, strlen(cKey), [hashData bytes], [hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    free(digest);
    cKey = nil;

    return result;
}

//MARK: HMAC-SHA224

+ (CocoaSecurityResult * _Nonnull)hmacSha224:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key {
    return [self hmacSha224WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding] hmacKey:key];
}

+ (CocoaSecurityResult * _Nonnull)hmacSha224WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key {
    unsigned char *digest;
    digest = malloc(CC_SHA224_DIGEST_LENGTH);
    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];

    CCHmac(kCCHmacAlgSHA224, cKey, strlen(cKey), [hashData bytes], [hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA224_DIGEST_LENGTH];
    free(digest);
    cKey = nil;

    return result;
}

//MARK: HMAC-SHA256

+ (CocoaSecurityResult * _Nonnull)hmacSha256:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key {
    return [self hmacSha256WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding] hmacKey:key];
}

+ (CocoaSecurityResult * _Nonnull)hmacSha256WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key {
    unsigned char *digest;
    digest = malloc(CC_SHA256_DIGEST_LENGTH);
    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];

    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), [hashData bytes], [hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    free(digest);
    cKey = nil;

    return result;
}

//MARK: HMAC-SHA384

+ (CocoaSecurityResult * _Nonnull)hmacSha384:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key {
    return [self hmacSha384WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding] hmacKey:key];
}

+ (CocoaSecurityResult * _Nonnull)hmacSha384WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key {
    unsigned char *digest;
    digest = malloc(CC_SHA384_DIGEST_LENGTH);
    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];

    CCHmac(kCCHmacAlgSHA384, cKey, strlen(cKey), [hashData bytes], [hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA384_DIGEST_LENGTH];
    free(digest);
    cKey = nil;

    return result;
}

//MARK: HMAC-SHA512

+ (CocoaSecurityResult * _Nonnull)hmacSha512:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key {
    return [self hmacSha512WithData:[hashString dataUsingEncoding:NSUTF8StringEncoding] hmacKey:key];
}

+ (CocoaSecurityResult * _Nonnull)hmacSha512WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key {
    unsigned char *digest;
    digest = malloc(CC_SHA512_DIGEST_LENGTH);
    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];

    CCHmac(kCCHmacAlgSHA512, cKey, strlen(cKey), [hashData bytes], [hashData length], digest);
    CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
    free(digest);
    cKey = nil;

    return result;
}

@end
