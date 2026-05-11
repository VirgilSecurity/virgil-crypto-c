/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package crypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"io"

	"github.com/VirgilSecurity/virgil-crypto-c/wrappers/go/foundation"
)

type PrivateKey interface {
	Identifier() []byte
	PublicKey() PublicKey
	Unwrap() foundation.PrivateKey
	KeyType() KeyType
}
type PublicKey interface {
	Export() ([]byte, error)
	Identifier() []byte
	Unwrap() foundation.PublicKey
	KeyType() KeyType
}

type Crypto struct {
	KeyType               KeyType
	UseSha256Fingerprints bool
}

var (
	signatureKey = []byte("VIRGIL-DATA-SIGNATURE")
	signerIDKey  = []byte("VIRGIL-DATA-SIGNER-ID")
)

func (c *Crypto) generateKeypair(t keyGen, rnd foundation.Random) (PrivateKey, error) {
	kp := foundation.NewKeyProvider()
	defer delete(kp)

	kp.SetRandom(rnd)

	sk, err := t.GeneratePrivateKey(kp)
	if err != nil {
		return nil, err
	}

	pk, err := sk.ExtractPublicKey()
	if err != nil {
		return nil, err
	}
	id, err := c.calculateFingerprint(pk)
	if err != nil {
		return nil, err
	}

	kt, err := getKeyType(sk)
	if err != nil {
		return nil, err
	}

	return &privateKey{
		receiverID: id,
		key:        sk, keyType: kt,
		publicKey: &publicKey{
			keyType:    kt,
			key:        pk,
			receiverID: id,
		},
	}, nil
}

func (c *Crypto) GenerateKeypairForType(t KeyType) (PrivateKey, error) {
	keyType, ok := keyTypeMap[t]
	if !ok {
		return nil, ErrUnsupportedKeyType
	}
	return c.generateKeypair(keyType, random)
}

func (c *Crypto) GenerateKeypair() (PrivateKey, error) {
	return c.GenerateKeypairForType(c.KeyType)
}

func (c *Crypto) GenerateKeypairFromKeyMaterialForType(t KeyType, keyMaterial []byte) (PrivateKey, error) {
	l := uint(len(keyMaterial))
	if l < foundation.KeyMaterialRngKeyMaterialLenMin || l > foundation.KeyMaterialRngKeyMaterialLenMax {
		return nil, ErrInvalidSeedSize
	}
	rnd := foundation.NewKeyMaterialRng()
	rnd.ResetKeyMaterial(keyMaterial)
	defer delete(rnd)

	return c.GenerateKeypairForTypeWithCustomRng(rnd, t)
}

func (c *Crypto) GenerateKeypairForTypeWithCustomRng(rnd foundation.Random, t KeyType) (PrivateKey, error) {
	keyType, ok := keyTypeMap[t]
	if !ok {
		return nil, ErrUnsupportedKeyType
	}

	return c.generateKeypair(keyType, rnd)
}

func (c *Crypto) GenerateKeypairFromKeyMaterial(keyMaterial []byte) (PrivateKey, error) {
	return c.GenerateKeypairFromKeyMaterialForType(c.KeyType, keyMaterial)
}

func (c *Crypto) Random(len int) ([]byte, error) {
	return random.Random(uint(len))
}

func (c *Crypto) ImportPrivateKey(data []byte) (PrivateKey, error) {
	data = unwrapKey(data)

	kp := foundation.NewKeyProvider()
	defer delete(kp)

	kp.SetRandom(random)
	if err := kp.SetupDefaults(); err != nil {
		return nil, err
	}

	sk, err := kp.ImportPrivateKey(data)
	if err != nil {
		return nil, err
	}

	pk, err := sk.ExtractPublicKey()
	if err != nil {
		return nil, err
	}
	id, err := c.calculateFingerprint(pk)
	if err != nil {
		return nil, err
	}

	kt, err := getKeyType(sk)
	if err != nil {
		return nil, err
	}

	return &privateKey{
		receiverID: id,
		key:        sk, keyType: kt,
		publicKey: &publicKey{
			keyType:    kt,
			key:        pk,
			receiverID: id,
		},
	}, nil
}

func (c *Crypto) ImportPublicKey(data []byte) (PublicKey, error) {
	data = unwrapKey(data)

	kp := foundation.NewKeyProvider()
	defer delete(kp)

	kp.SetRandom(random)
	if err := kp.SetupDefaults(); err != nil {
		return nil, err
	}
	pk, err := kp.ImportPublicKey(data)
	if err != nil {
		return nil, err
	}

	id, err := c.calculateFingerprint(pk)
	if err != nil {
		return nil, err
	}

	kt, err := getKeyType(pk)
	if err != nil {
		return nil, err
	}

	return &publicKey{receiverID: id, key: pk, keyType: kt}, nil
}

func (c *Crypto) ExportPrivateKey(key PrivateKey) ([]byte, error) {
	kp := foundation.NewKeyProvider()
	defer delete(kp)

	kp.SetRandom(random)
	if err := kp.SetupDefaults(); err != nil {
		return nil, err
	}
	return kp.ExportPrivateKey(key.Unwrap())
}

func (c *Crypto) ExportPublicKey(key PublicKey) ([]byte, error) {
	return key.Export()
}

func (c *Crypto) calculateFingerprint(key foundation.PublicKey) ([]byte, error) {
	kp := foundation.NewKeyProvider()
	defer delete(kp)

	kp.SetRandom(random)
	if err := kp.SetupDefaults(); err != nil {
		return nil, err
	}

	data, err := kp.ExportPublicKey(key)
	if err != nil {
		return nil, err
	}

	if c.UseSha256Fingerprints {
		hash := sha256.Sum256(data)
		return hash[:], nil
	}

	hash := sha512.Sum512(data)
	return hash[:8], nil
}

func (c *Crypto) Encrypt(data []byte, recipients ...PublicKey) ([]byte, error) {
	return c.EncryptWithPadding(data, false, recipients...)
}

func (c *Crypto) EncryptWithPadding(data []byte, padding bool, recipients ...PublicKey) ([]byte, error) {
	cipher, err := c.setupEncryptCipher(recipients, padding)
	if err != nil {
		return nil, err
	}
	defer delete(cipher)

	buffer := bytes.NewBuffer(nil)
	buffer.Grow(len(data))

	dst := NewEncryptWriter(NopWriteCloser(buffer), cipher)
	src := bytes.NewReader(data)
	if err := copyClose(dst, src); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (c *Crypto) Decrypt(data []byte, key PrivateKey) ([]byte, error) {

	cipher := c.setupCipher(false)
	defer delete(cipher)

	if err := cipher.StartDecryptionWithKey(key.Identifier(), key.Unwrap(), nil); err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(nil)
	dr := NewDecryptReader(bytes.NewReader(data), cipher)
	if _, err := io.Copy(buf, dr); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (c *Crypto) EncryptStream(in io.Reader, out io.Writer, recipients ...PublicKey) (err error) {
	return c.EncryptStreamWithPadding(in, out, false, recipients...)
}

func (c *Crypto) EncryptStreamWithPadding(in io.Reader, out io.Writer, padding bool, recipients ...PublicKey) (err error) {
	cipher, err := c.setupEncryptCipher(recipients, padding)
	if err != nil {
		return err
	}
	defer delete(cipher)

	dst := NewEncryptWriter(NopWriteCloser(out), cipher)
	if err := copyClose(dst, in); err != nil {
		return err
	}

	return nil
}

func (c *Crypto) DecryptStream(in io.Reader, out io.Writer, key PrivateKey) (err error) {

	cipher := c.setupCipher(false)
	defer delete(cipher)

	if err = cipher.StartDecryptionWithKey(key.Identifier(), key.Unwrap(), nil); err != nil {
		return err
	}

	dr := NewDecryptReader(in, cipher)
	if _, err := io.Copy(out, dr); err != nil {
		return err
	}

	return nil
}

func (c *Crypto) Sign(data []byte, signer PrivateKey) ([]byte, error) {
	s := foundation.NewSigner()
	h := foundation.NewSha512()
	defer delete(s, h)

	s.SetRandom(random)
	s.SetHash(h)
	s.Reset()
	s.AppendData(data)

	return s.Sign(signer.Unwrap())
}

func (c *Crypto) VerifySignature(data []byte, signature []byte, key PublicKey) error {

	v := foundation.NewVerifier()
	defer delete(v)

	if err := v.Reset(signature); err != nil {
		return err
	}
	v.AppendData(data)

	if v.Verify(key.Unwrap()) {
		return nil
	}
	return ErrSignVerification
}

func (c *Crypto) SignStream(in io.Reader, signer PrivateKey) ([]byte, error) {
	s := foundation.NewSigner()
	h := foundation.NewSha512()
	defer delete(s, h)

	s.SetRandom(random)
	s.SetHash(h)
	s.Reset()
	if _, err := io.Copy(&appenderWriter{s}, in); err != nil {
		return nil, err
	}

	return s.Sign(signer.Unwrap())
}

func (c *Crypto) VerifyStream(in io.Reader, signature []byte, key PublicKey) error {
	v := foundation.NewVerifier()
	defer delete(v)

	if err := v.Reset(signature); err != nil {
		return err
	}
	if _, err := io.Copy(&appenderWriter{v}, in); err != nil {
		return err
	}

	if v.Verify(key.Unwrap()) {
		return nil
	}
	return ErrSignVerification
}

func (c *Crypto) SignThenEncrypt(data []byte, signer PrivateKey, recipients ...PublicKey) ([]byte, error) {
	return c.SignThenEncryptWithPadding(data, signer, true, recipients...)
}

func (c *Crypto) SignThenEncryptWithPadding(data []byte, signer PrivateKey, padding bool, recipients ...PublicKey) ([]byte, error) {
	cipher, err := c.setupEncryptCipher(recipients, padding)
	if err != nil {
		return nil, err
	}
	h := foundation.NewSha512()

	defer delete(cipher, h)

	cipher.SetSignerHash(h)
	if err = cipher.AddSigner(signer.Identifier(), signer.Unwrap()); err != nil {
		return nil, err
	}
	if err = cipher.StartSignedEncryption(uint(len(data))); err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(nil)

	dst := NewEncryptWriter(NopWriteCloser(buffer), cipher)
	src := bytes.NewReader(data)
	if err = copyClose(dst, src); err != nil {
		return nil, err
	}

	buf, err := cipher.PackMessageInfoFooter()
	if err != nil {
		return nil, err
	}
	if _, err = buffer.Write(buf); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (c *Crypto) DecryptThenVerify(
	data []byte,
	decryptionKey PrivateKey,
	verifierKeys ...PublicKey,
) (_ []byte, err error) {
	cipher := c.setupCipher(false)
	defer delete(cipher)

	if err := cipher.StartDecryptionWithKey(decryptionKey.Identifier(), decryptionKey.Unwrap(), nil); err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(nil)
	if _, err := io.Copy(buffer, NewDecryptReader(bytes.NewReader(data), cipher)); err != nil {
		return nil, err
	}
	if err := c.verifyCipherSign(cipher, verifierKeys); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (c *Crypto) SignThenEncryptStream(
	in io.Reader,
	out io.Writer,
	streamSize int,
	signer PrivateKey,
	recipients ...PublicKey,
) (err error) {
	return c.SignThenEncryptStreamWithPadding(in, out, streamSize, signer, false, recipients...)
}

func (c *Crypto) SignThenEncryptStreamWithPadding(
	in io.Reader,
	out io.Writer,
	streamSize int,
	signer PrivateKey,
	padding bool,
	recipients ...PublicKey,
) (err error) {
	if streamSize < 0 {
		return ErrStreamSizeIncorrect
	}

	var (
		cipher *foundation.RecipientCipher
		h      foundation.Hash
	)
	defer delete(cipher, h)

	cipher, err = c.setupEncryptCipher(recipients, padding)
	if err != nil {
		return err
	}

	h = foundation.NewSha512()
	cipher.SetSignerHash(h)
	if err = cipher.AddSigner(signer.Identifier(), signer.Unwrap()); err != nil {
		return err
	}
	if err = cipher.StartSignedEncryption(uint(streamSize)); err != nil {
		return err
	}

	dst := NewEncryptWriter(NopWriteCloser(out), cipher)
	if err = copyClose(dst, in); err != nil {
		return err
	}

	buf, err := cipher.PackMessageInfoFooter()
	if err != nil {
		return err
	}
	if _, err = out.Write(buf); err != nil {
		return err
	}

	return nil
}

func (c *Crypto) DecryptThenVerifyStream(
	in io.Reader,
	out io.Writer,
	decryptionKey PrivateKey,
	verifierKeys ...PublicKey,
) error {

	cipher := c.setupCipher(false)
	defer delete(cipher)

	if err := cipher.StartDecryptionWithKey(decryptionKey.Identifier(), decryptionKey.Unwrap(), nil); err != nil {
		return err
	}

	if _, err := io.Copy(out, NewDecryptReader(in, cipher)); err != nil {
		return err
	}

	return c.verifyCipherSign(cipher, verifierKeys)
}

func (c *Crypto) SignAndEncrypt(data []byte, signer PrivateKey, recipients ...PublicKey) (_ []byte, err error) {
	return c.SignAndEncryptWithPadding(data, signer, false, recipients...)
}

func (c *Crypto) SignAndEncryptWithPadding(data []byte, signer PrivateKey, padding bool, recipients ...PublicKey) (_ []byte, err error) {
	var (
		cipher *foundation.RecipientCipher
		params *foundation.MessageInfoCustomParams
	)
	defer delete(cipher, params)

	cipher, err = c.setupEncryptCipher(recipients, padding)
	if err != nil {
		return nil, err
	}

	sign, err := c.Sign(data, signer)
	if err != nil {
		return nil, err
	}

	params = cipher.CustomParams()
	params.AddData(signatureKey, sign)
	params.AddData(signerIDKey, signer.Identifier())

	if err := cipher.StartEncryption(); err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(nil)
	buffer.Grow(len(data))

	dst := NewEncryptWriter(NopWriteCloser(buffer), cipher)
	src := bytes.NewReader(data)
	if err := copyClose(dst, src); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (c *Crypto) DecryptAndVerify(data []byte, decryptionKey PrivateKey, verifierKeys ...PublicKey) (_ []byte, err error) {
	var (
		cipher *foundation.RecipientCipher
		params *foundation.MessageInfoCustomParams
	)
	defer delete(cipher, params)

	cipher = c.setupCipher(false)
	if err = cipher.StartDecryptionWithKey(decryptionKey.Identifier(), decryptionKey.Unwrap(), nil); err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(nil)
	if _, err = io.Copy(buffer, NewDecryptReader(bytes.NewReader(data), cipher)); err != nil {
		return nil, err
	}

	params = cipher.CustomParams()
	signerID, err := params.FindData(signerIDKey)
	if err != nil {
		return nil, err
	}

	sign, err := params.FindData(signatureKey)
	if err != nil {
		return nil, err
	}

	k, err := findVerifyKey(signerID, verifierKeys)
	if err != nil {
		return nil, err
	}

	if err := c.VerifySignature(buffer.Bytes(), sign, k); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (c *Crypto) Hash(data []byte, t HashType) ([]byte, error) {
	hf, ok := hashMap[t]
	if !ok {
		return nil, ErrUnsupportedHashType
	}
	hash := hf().Hash(data)

	return hash, nil
}

func (c *Crypto) verifyCipherSign(cipher *foundation.RecipientCipher, verifierKeys []PublicKey) error {
	var (
		signerInfoList *foundation.SignerInfoList
		signInfo       *foundation.SignerInfo
	)
	defer delete(signerInfoList, signInfo)

	if !cipher.IsDataSigned() {
		return ErrSignNotFound
	}

	signerInfoList = cipher.SignerInfos()
	if !signerInfoList.HasItem() {
		return ErrSignNotFound
	}

	signInfo = signerInfoList.Item()
	k, err := findVerifyKey(signInfo.SignerId(), verifierKeys)
	if err != nil {
		return err
	}

	if cipher.VerifySignerInfo(signInfo, k.Unwrap()) {
		return nil
	}
	return ErrSignVerification
}

func findVerifyKey(signerID []byte, verifierKeys []PublicKey) (PublicKey, error) {
	for _, r := range verifierKeys {
		//TODO: check that it's really need
		if subtle.ConstantTimeCompare(signerID, r.Identifier()) == 1 {
			return r, nil
		}
	}
	return nil, ErrSignNotFound
}

const paddingLen uint = 160

func (c *Crypto) setupCipher(padding bool) *foundation.RecipientCipher {
	aesGcm := foundation.NewAes256Gcm()
	cipher := foundation.NewRecipientCipher()
	defer delete(aesGcm)

	cipher.SetEncryptionCipher(aesGcm)
	cipher.SetRandom(random)

	if padding {
		padding := foundation.NewRandomPadding()
		padding.SetRandom(random)
		cipher.SetEncryptionPadding(padding)
		paddingParams := foundation.NewPaddingParamsWithConstraints(paddingLen, paddingLen)
		cipher.SetPaddingParams(paddingParams)
		delete(padding)
	}
	return cipher
}

func (c *Crypto) setupEncryptCipher(recipients []PublicKey, padding bool) (*foundation.RecipientCipher, error) {
	cipher := c.setupCipher(padding)

	if err := c.setupRecipients(cipher, recipients); err != nil {
		return nil, err
	}
	return cipher, nil
}

func (c *Crypto) setupRecipients(cipher *foundation.RecipientCipher, recipients []PublicKey) error {
	for _, r := range recipients {
		cipher.AddKeyRecipient(r.Identifier(), r.Unwrap())
	}
	if err := cipher.StartEncryption(); err != nil {
		return err
	}
	return nil
}

func copyClose(dst io.WriteCloser, src io.Reader) error {
	_, err := io.Copy(dst, src)
	if err != nil {
		return err
	}
	return dst.Close()
}

type appender interface {
	AppendData(b []byte)
}

type appenderWriter struct {
	a appender
}

func (aw *appenderWriter) Write(d []byte) (int, error) {
	aw.a.AppendData(d)
	return len(d), nil
}
