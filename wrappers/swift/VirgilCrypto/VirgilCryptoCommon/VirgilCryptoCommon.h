//
//  VirgilCryptoCommon.h
//  VirgilCryptoCommon
//
//  Created by Sergey Seroshtan on 10/11/18.
//  Copyright © 2018 Virgil Security, Inc. All rights reserved.
//

#import "TargetConditionals.h"

#if TARGET_OS_IPHONE
#   import <UIKit/UIKit.h>
#else
#   import <Cocoa/Cocoa.h>
#endif

//! Project version number for VirgilCryptoCommon.
FOUNDATION_EXPORT double VirgilCryptoCommonVersionNumber;

//! Project version string for VirgilCryptoCommon.
FOUNDATION_EXPORT const unsigned char VirgilCryptoCommonVersionString[];
