//
//  VirgilCryptoPythia.h
//  VirgilCryptoPythia
//
//  Created by Sergey Seroshtan on 10/14/18.
//  Copyright © 2018 Virgil Security, Inc. All rights reserved.
//

#import "TargetConditionals.h"

#if TARGET_OS_IPHONE
#   import <UIKit/UIKit.h>
#else
#   import <Cocoa/Cocoa.h>
#endif

//! Project version number for VirgilCryptoPythia.
FOUNDATION_EXPORT double VirgilCryptoPythiaVersionNumber;

//! Project version string for VirgilCryptoPythia.
FOUNDATION_EXPORT const unsigned char VirgilCryptoPythiaVersionString[];
