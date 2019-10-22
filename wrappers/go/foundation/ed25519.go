package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* This is implementation of Ed25519 elliptic curve algorithms.
*/
type Ed25519 struct {
    IAlg
    IKeyAlg
    IKeyCipher
    IKeySigner
    IComputeSharedKey
    ctx *C.vscf_impl_t
}

func (this Ed25519) SetRandom (random IRandom) {
    C.vscf_ed25519_release_random(this.ctx)
    C.vscf_ed25519_use_random(this.ctx, random.Ctx())
}

func (this Ed25519) SetEcies (ecies Ecies) {
    C.vscf_ed25519_release_ecies(this.ctx)
    C.vscf_ed25519_use_ecies(this.ctx, ecies.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Ed25519) SetupDefaults () {
    proxyResult := C.vscf_ed25519_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Generate new private key.
* Note, this operation might be slow.
*/
func (this Ed25519) GenerateKey () IPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ed25519_generate_key(this.ctx, &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this Ed25519) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewEd25519 () *Ed25519 {
    ctx := C.vscf_ed25519_new()
    return &Ed25519 {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEd25519WithCtx (ctx *C.vscf_impl_t) *Ed25519 {
    return &Ed25519 {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEd25519Copy (ctx *C.vscf_impl_t) *Ed25519 {
    return &Ed25519 {
        ctx: C.vscf_ed25519_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Ed25519) AlgId () AlgId {
    proxyResult := C.vscf_ed25519_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Ed25519) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_ed25519_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Ed25519) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_ed25519_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Defines whether a public key can be imported or not.
*/
func (this Ed25519) getCanImportPublicKey () bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (this Ed25519) getCanExportPublicKey () bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (this Ed25519) getCanImportPrivateKey () bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (this Ed25519) getCanExportPrivateKey () bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (this Ed25519) GenerateEphemeralKey (key IKey) IPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ed25519_generate_ephemeral_key(this.ctx, key.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Import public key from the raw binary format.
*
* Return public key that is adopted and optimized to be used
* with this particular algorithm.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be imported from the format defined in
* RFC 3447 Appendix A.1.1.
*/
func (this Ed25519) ImportPublicKey (rawKey RawPublicKey) IPublicKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ed25519_import_public_key(this.ctx, rawKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}

/*
* Export public key to the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be exported in format defined in
* RFC 3447 Appendix A.1.1.
*/
func (this Ed25519) ExportPublicKey (publicKey IPublicKey) RawPublicKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ed25519_export_public_key(this.ctx, publicKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewRawPublicKeyWithCtx(proxyResult) /* r6 */
}

/*
* Import private key from the raw binary format.
*
* Return private key that is adopted and optimized to be used
* with this particular algorithm.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be imported from the format defined in
* RFC 3447 Appendix A.1.2.
*/
func (this Ed25519) ImportPrivateKey (rawKey RawPrivateKey) IPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ed25519_import_private_key(this.ctx, rawKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Export private key in the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be exported in format defined in
* RFC 3447 Appendix A.1.2.
*/
func (this Ed25519) ExportPrivateKey (privateKey IPrivateKey) RawPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_ed25519_export_private_key(this.ctx, privateKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewRawPrivateKeyWithCtx(proxyResult) /* r6 */
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (this Ed25519) CanEncrypt (publicKey IPublicKey, dataLen int32) bool {
    proxyResult := C.vscf_ed25519_can_encrypt(this.ctx, publicKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Ed25519) EncryptedLen (publicKey IPublicKey, dataLen int32) int32 {
    proxyResult := C.vscf_ed25519_encrypted_len(this.ctx, publicKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Encrypt data with a given public key.
*/
func (this Ed25519) Encrypt (publicKey IPublicKey, data []byte) []byte {
    outCount := this.EncryptedLen(publicKey, int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_ed25519_encrypt(this.ctx, publicKey.Ctx(), WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Check if algorithm can decrypt data with a given key.
* However, success result of decryption is not guaranteed.
*/
func (this Ed25519) CanDecrypt (privateKey IPrivateKey, dataLen int32) bool {
    proxyResult := C.vscf_ed25519_can_decrypt(this.ctx, privateKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Ed25519) DecryptedLen (privateKey IPrivateKey, dataLen int32) int32 {
    proxyResult := C.vscf_ed25519_decrypted_len(this.ctx, privateKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Decrypt given data.
*/
func (this Ed25519) Decrypt (privateKey IPrivateKey, data []byte) []byte {
    outCount := this.DecryptedLen(privateKey, int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_ed25519_decrypt(this.ctx, privateKey.Ctx(), WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (this Ed25519) CanSign (privateKey IPrivateKey) bool {
    proxyResult := C.vscf_ed25519_can_sign(this.ctx, privateKey.Ctx())

    return proxyResult //r9
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (this Ed25519) SignatureLen (key IKey) int32 {
    proxyResult := C.vscf_ed25519_signature_len(this.ctx, key.Ctx())

    return proxyResult //r9
}

/*
* Sign data digest with a given private key.
*/
func (this Ed25519) SignHash (privateKey IPrivateKey, hashId AlgId, digest []byte) []byte {
    signatureCount := this.SignatureLen(privateKey) /* lg2 */
    signatureBuf := NewBuffer(signatureCount)
    defer signatureBuf.Clear()


    proxyResult := C.vscf_ed25519_sign_hash(this.ctx, privateKey.Ctx(), hashId /*pa7*/, WrapData(digest), signatureBuf)

    FoundationErrorHandleStatus(proxyResult)

    return signatureBuf.GetData() /* r7 */
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (this Ed25519) CanVerify (publicKey IPublicKey) bool {
    proxyResult := C.vscf_ed25519_can_verify(this.ctx, publicKey.Ctx())

    return proxyResult //r9
}

/*
* Verify data digest with a given public key and signature.
*/
func (this Ed25519) VerifyHash (publicKey IPublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    proxyResult := C.vscf_ed25519_verify_hash(this.ctx, publicKey.Ctx(), hashId /*pa7*/, WrapData(digest), WrapData(signature))

    return proxyResult //r9
}

/*
* Compute shared key for 2 asymmetric keys.
* Note, computed shared key can be used only within symmetric cryptography.
*/
func (this Ed25519) ComputeSharedKey (publicKey IPublicKey, privateKey IPrivateKey) []byte {
    sharedKeyCount := this.SharedKeyLen(privateKey) /* lg2 */
    sharedKeyBuf := NewBuffer(sharedKeyCount)
    defer sharedKeyBuf.Clear()


    proxyResult := C.vscf_ed25519_compute_shared_key(this.ctx, publicKey.Ctx(), privateKey.Ctx(), sharedKeyBuf)

    FoundationErrorHandleStatus(proxyResult)

    return sharedKeyBuf.GetData() /* r7 */
}

/*
* Return number of bytes required to hold shared key.
* Expect Public Key or Private Key.
*/
func (this Ed25519) SharedKeyLen (key IKey) int32 {
    proxyResult := C.vscf_ed25519_shared_key_len(this.ctx, key.Ctx())

    return proxyResult //r9
}
