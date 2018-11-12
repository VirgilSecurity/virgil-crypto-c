//
//  VirgilCryptoFoundation.h
//  VirgilCryptoFoundation
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

//! Project version number for VirgilCryptoFoundation.
FOUNDATION_EXPORT double VirgilCryptoFoundationVersionNumber;

//! Project version string for VirgilCryptoFoundation.
FOUNDATION_EXPORT const unsigned char VirgilCryptoFoundationVersionString[];
