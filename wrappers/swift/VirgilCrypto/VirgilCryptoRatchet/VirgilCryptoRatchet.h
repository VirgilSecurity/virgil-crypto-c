//
//  VirgilCryptoRatchet.h
//  VirgilCryptoRatchet
//
//  Created by Sergey Seroshtan on 10/26/18.
//  Copyright © 2018 Virgil Security, Inc. All rights reserved.
//

#import "TargetConditionals.h"

#if TARGET_OS_IPHONE
#   import <UIKit/UIKit.h>
#else
#   import <Cocoa/Cocoa.h>
#endif

//! Project version number for VirgilCryptoRatchet.
FOUNDATION_EXPORT double VirgilCryptoRatchetVersionNumber;

//! Project version string for VirgilCryptoRatchet.
FOUNDATION_EXPORT const unsigned char VirgilCryptoRatchetVersionString[];
