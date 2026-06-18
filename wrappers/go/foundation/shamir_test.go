//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package foundation

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var testShamirSecret = []byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
}

//  Pick the shares at the given indices out of a `count`-share concatenation.
func selectShares(shares []byte, count uint, indices ...uint) []byte {
	shareSize := uint(len(shares)) / count
	selection := make([]byte, 0, shareSize*uint(len(indices)))
	for _, idx := range indices {
		selection = append(selection, shares[idx*shareSize:(idx+1)*shareSize]...)
	}
	return selection
}

func newTestShamir(t *testing.T) *Shamir {
	shamir := NewShamir()
	require.Nil(t, shamir.SetupDefaults())
	return shamir
}

func TestShamirSplitCombine2of3EveryPair(t *testing.T) {
	shamir := newTestShamir(t)
	defer shamir.Delete()

	shares, err := shamir.Split(testShamirSecret, 2, 3)
	require.Nil(t, err)

	for _, pair := range [][]uint{{0, 1}, {0, 2}, {1, 2}, {2, 0}} {
		recovered, cErr := shamir.Combine(selectShares(shares, 3, pair...), 2)
		require.Nil(t, cErr)
		require.Equal(t, testShamirSecret, recovered)
	}
}

func TestShamirSplitCombineGeneralKofN(t *testing.T) {
	shamir := newTestShamir(t)
	defer shamir.Delete()

	shares, err := shamir.Split(testShamirSecret, 5, 7)
	require.Nil(t, err)

	recovered, err := shamir.Combine(selectShares(shares, 7, 6, 4, 2, 1, 0), 5)
	require.Nil(t, err)
	require.Equal(t, testShamirSecret, recovered)
}

func TestShamirCombineInsufficientShares(t *testing.T) {
	shamir := newTestShamir(t)
	defer shamir.Delete()

	shares, err := shamir.Split(testShamirSecret, 3, 5)
	require.Nil(t, err)

	_, cErr := shamir.Combine(selectShares(shares, 5, 0, 1), 2)
	require.NotNil(t, cErr) // wrong/insufficient -> recovery fails
}

func TestShamirCombineDuplicateShare(t *testing.T) {
	shamir := newTestShamir(t)
	defer shamir.Delete()

	shares, err := shamir.Split(testShamirSecret, 2, 3)
	require.Nil(t, err)

	_, cErr := shamir.Combine(selectShares(shares, 3, 1, 1), 2)
	require.NotNil(t, cErr) // colliding x-coordinate -> bad arguments
}

func TestShamirCombineTamperedShare(t *testing.T) {
	shamir := newTestShamir(t)
	defer shamir.Delete()

	shares, err := shamir.Split(testShamirSecret, 2, 3)
	require.Nil(t, err)

	//  Flip a ciphertext byte (offset 68 = envelope header length) of share 0.
	shares[68] ^= 0x01
	_, cErr := shamir.Combine(selectShares(shares, 3, 0, 1), 2)
	require.NotNil(t, cErr)
}

func TestShamirSplitInvalidThreshold(t *testing.T) {
	shamir := newTestShamir(t)
	defer shamir.Delete()

	_, err := shamir.Split(testShamirSecret, 4, 3) // k > n
	require.NotNil(t, err)
}
