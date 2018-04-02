//
//  Constants.m
//  CocoaSecurity
//
//  Created by Vadim Zhilinkov on 31/03/2018.
//

#import "Constants.h"

const unsigned char kHexDecodeChars[] = {
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

const char kHexEncodeChars[] = "0123456789ABCDEF";

const char kHexEncodeCharsLower[] = "0123456789abcdef";


