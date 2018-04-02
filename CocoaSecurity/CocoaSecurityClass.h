//
//  CocoaSecurityClass.h
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

@import Foundation;


@class CocoaSecurityResult;


@interface CocoaSecurity : NSObject

//MARK: - AES Encrypt

+ (CocoaSecurityResult * _Nonnull)aesEncrypt:(NSString * _Nonnull)data key:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)aesEncrypt:(NSString * _Nonnull)data hexKey:(NSString * _Nonnull)key hexIv:(NSString * _Nonnull)iv;
+ (CocoaSecurityResult * _Nonnull)aesEncrypt:(NSString * _Nonnull)data key:(NSData * _Nonnull)key iv:(NSData * _Nonnull)iv;
+ (CocoaSecurityResult * _Nonnull)aesEncryptWithData:(NSData * _Nonnull)data key:(NSData * _Nonnull)key iv:(NSData * _Nonnull)iv;


//MARK: - AES Decrypt

+ (CocoaSecurityResult * _Nonnull)aesDecryptWithBase64:(NSString * _Nonnull)data key:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)aesDecryptWithBase64:(NSString * _Nonnull)data hexKey:(NSString * _Nonnull)key hexIv:(NSString * _Nonnull)iv;
+ (CocoaSecurityResult * _Nonnull)aesDecryptWithBase64:(NSString * _Nonnull)data key:(NSData * _Nonnull)key iv:(NSData * _Nonnull)iv;
+ (CocoaSecurityResult * _Nonnull)aesDecryptWithData:(NSData * _Nonnull)data key:(NSData * _Nonnull)key iv:(NSData * _Nonnull)iv;


//MARK: - MD5

+ (CocoaSecurityResult * _Nonnull)md5:(NSString * _Nonnull)hashString;
+ (CocoaSecurityResult * _Nonnull)md5WithData:(NSData * _Nonnull)hashData;


//MARK: HMAC-MD5

+ (CocoaSecurityResult * _Nonnull)hmacMd5:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacMd5WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key;


//MARK: - SHA

+ (CocoaSecurityResult * _Nonnull)sha1:(NSString * _Nonnull)hashString;
+ (CocoaSecurityResult * _Nonnull)sha1WithData:(NSData * _Nonnull)hashData;
+ (CocoaSecurityResult * _Nonnull)sha224:(NSString * _Nonnull)hashString;
+ (CocoaSecurityResult * _Nonnull)sha224WithData:(NSData * _Nonnull)hashData;
+ (CocoaSecurityResult * _Nonnull)sha256:(NSString * _Nonnull)hashString;
+ (CocoaSecurityResult * _Nonnull)sha256WithData:(NSData * _Nonnull)hashData;
+ (CocoaSecurityResult * _Nonnull)sha384:(NSString * _Nonnull)hashString;
+ (CocoaSecurityResult * _Nonnull)sha384WithData:(NSData * _Nonnull)hashData;
+ (CocoaSecurityResult * _Nonnull)sha512:(NSString * _Nonnull)hashString;
+ (CocoaSecurityResult * _Nonnull)sha512WithData:(NSData * _Nonnull)hashData;


//MARK: HMAC-SHA

+ (CocoaSecurityResult * _Nonnull)hmacSha1:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha1WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha224:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha224WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha256:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha256WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha384:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha384WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha512:(NSString * _Nonnull)hashString hmacKey:(NSString * _Nonnull)key;
+ (CocoaSecurityResult * _Nonnull)hmacSha512WithData:(NSData * _Nonnull)hashData hmacKey:(NSString * _Nonnull)key;

@end
