package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* RSA implementation.
*/
type Rsa struct {
    IAlg
    IKeyAlg
    IKeyCipher
    IKeySigner
    ctx *C.vscf_impl_t
}

func (this Rsa) SetRandom (random IRandom) {
    C.vscf_rsa_release_random(this.ctx)
    C.vscf_rsa_use_random(this.ctx, random.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Rsa) SetupDefaults () {
    proxyResult := C.vscf_rsa_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Generate new private key.
* Note, this operation might be slow.
*/
func (this Rsa) GenerateKey (bitlen int32) IPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_rsa_generate_key(this.ctx, bitlen, &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this Rsa) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewRsa () *Rsa {
    ctx := C.vscf_rsa_new()
    return &Rsa {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRsaWithCtx (ctx *C.vscf_impl_t) *Rsa {
    return &Rsa {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRsaCopy (ctx *C.vscf_impl_t) *Rsa {
    return &Rsa {
        ctx: C.vscf_rsa_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Rsa) AlgId () AlgId {
    proxyResult := C.vscf_rsa_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Rsa) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_rsa_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Rsa) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_rsa_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Defines whether a public key can be imported or not.
*/
func (this Rsa) getCanImportPublicKey () bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func (this Rsa) getCanExportPublicKey () bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func (this Rsa) getCanImportPrivateKey () bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func (this Rsa) getCanExportPrivateKey () bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (this Rsa) GenerateEphemeralKey (key IKey) IPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_rsa_generate_ephemeral_key(this.ctx, key.Ctx(), &error)

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
func (this Rsa) ImportPublicKey (rawKey RawPublicKey) IPublicKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_rsa_import_public_key(this.ctx, rawKey.Ctx(), &error)

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
func (this Rsa) ExportPublicKey (publicKey IPublicKey) RawPublicKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_rsa_export_public_key(this.ctx, publicKey.Ctx(), &error)

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
func (this Rsa) ImportPrivateKey (rawKey RawPrivateKey) IPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_rsa_import_private_key(this.ctx, rawKey.Ctx(), &error)

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
func (this Rsa) ExportPrivateKey (privateKey IPrivateKey) RawPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_rsa_export_private_key(this.ctx, privateKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewRawPrivateKeyWithCtx(proxyResult) /* r6 */
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (this Rsa) CanEncrypt (publicKey IPublicKey, dataLen int32) bool {
    proxyResult := C.vscf_rsa_can_encrypt(this.ctx, publicKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Rsa) EncryptedLen (publicKey IPublicKey, dataLen int32) int32 {
    proxyResult := C.vscf_rsa_encrypted_len(this.ctx, publicKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Encrypt data with a given public key.
*/
func (this Rsa) Encrypt (publicKey IPublicKey, data []byte) []byte {
    outCount := this.EncryptedLen(publicKey, int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_rsa_encrypt(this.ctx, publicKey.Ctx(), WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Check if algorithm can decrypt data with a given key.
* However, success result of decryption is not guaranteed.
*/
func (this Rsa) CanDecrypt (privateKey IPrivateKey, dataLen int32) bool {
    proxyResult := C.vscf_rsa_can_decrypt(this.ctx, privateKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Rsa) DecryptedLen (privateKey IPrivateKey, dataLen int32) int32 {
    proxyResult := C.vscf_rsa_decrypted_len(this.ctx, privateKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Decrypt given data.
*/
func (this Rsa) Decrypt (privateKey IPrivateKey, data []byte) []byte {
    outCount := this.DecryptedLen(privateKey, int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_rsa_decrypt(this.ctx, privateKey.Ctx(), WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (this Rsa) CanSign (privateKey IPrivateKey) bool {
    proxyResult := C.vscf_rsa_can_sign(this.ctx, privateKey.Ctx())

    return proxyResult //r9
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (this Rsa) SignatureLen (key IKey) int32 {
    proxyResult := C.vscf_rsa_signature_len(this.ctx, key.Ctx())

    return proxyResult //r9
}

/*
* Sign data digest with a given private key.
*/
func (this Rsa) SignHash (privateKey IPrivateKey, hashId AlgId, digest []byte) []byte {
    signatureCount := this.SignatureLen(privateKey) /* lg2 */
    signatureBuf := NewBuffer(signatureCount)
    defer signatureBuf.Clear()


    proxyResult := C.vscf_rsa_sign_hash(this.ctx, privateKey.Ctx(), hashId /*pa7*/, WrapData(digest), signatureBuf)

    FoundationErrorHandleStatus(proxyResult)

    return signatureBuf.GetData() /* r7 */
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (this Rsa) CanVerify (publicKey IPublicKey) bool {
    proxyResult := C.vscf_rsa_can_verify(this.ctx, publicKey.Ctx())

    return proxyResult //r9
}

/*
* Verify data digest with a given public key and signature.
*/
func (this Rsa) VerifyHash (publicKey IPublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    proxyResult := C.vscf_rsa_verify_hash(this.ctx, publicKey.Ctx(), hashId /*pa7*/, WrapData(digest), WrapData(signature))

    return proxyResult //r9
}
