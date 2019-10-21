package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Implementation of the symmetric cipher AES-256 bit in a GCM mode.
* Note, this implementation contains dynamic memory allocations,
* this should be improved in the future releases.
*/
type Aes256Gcm struct {
    IAlg
    IEncrypt
    IDecrypt
    ICipherInfo
    ICipher
    ICipherAuthInfo
    IAuthEncrypt
    IAuthDecrypt
    ICipherAuth
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Aes256Gcm) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewAes256Gcm () *Aes256Gcm {
    ctx := C.vscf_aes256_gcm_new()
    return &Aes256Gcm {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAes256GcmWithCtx (ctx *C.vscf_impl_t) *Aes256Gcm {
    return &Aes256Gcm {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAes256GcmCopy (ctx *C.vscf_impl_t) *Aes256Gcm {
    return &Aes256Gcm {
        ctx: C.vscf_aes256_gcm_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Aes256Gcm) AlgId () AlgId {
    proxyResult := C.vscf_aes256_gcm_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Aes256Gcm) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_aes256_gcm_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Aes256Gcm) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_aes256_gcm_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Encrypt given data.
*/
func (this Aes256Gcm) Encrypt (data []byte) []byte {
    outCount := this.EncryptedLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_aes256_gcm_encrypt(this.ctx, WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Aes256Gcm) EncryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_gcm_encrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Precise length calculation of encrypted data.
*/
func (this Aes256Gcm) PreciseEncryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_gcm_precise_encrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Decrypt given data.
*/
func (this Aes256Gcm) Decrypt (data []byte) []byte {
    outCount := this.DecryptedLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_aes256_gcm_decrypt(this.ctx, WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Aes256Gcm) DecryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_gcm_decrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
*/
func (this Aes256Gcm) getNonceLen () int32 {
    return 12
}

/*
* Cipher key length in bytes.
*/
func (this Aes256Gcm) getKeyLen () int32 {
    return 32
}

/*
* Cipher key length in bits.
*/
func (this Aes256Gcm) getKeyBitlen () int32 {
    return 256
}

/*
* Cipher block length in bytes.
*/
func (this Aes256Gcm) getBlockLen () int32 {
    return 16
}

/*
* Setup IV or nonce.
*/
func (this Aes256Gcm) SetNonce (nonce []byte) {
    C.vscf_aes256_gcm_set_nonce(this.ctx, WrapData(nonce))
}

/*
* Set cipher encryption / decryption key.
*/
func (this Aes256Gcm) SetKey (key []byte) {
    C.vscf_aes256_gcm_set_key(this.ctx, WrapData(key))
}

/*
* Start sequential encryption.
*/
func (this Aes256Gcm) StartEncryption () {
    C.vscf_aes256_gcm_start_encryption(this.ctx)
}

/*
* Start sequential decryption.
*/
func (this Aes256Gcm) StartDecryption () {
    C.vscf_aes256_gcm_start_decryption(this.ctx)
}

/*
* Process encryption or decryption of the given data chunk.
*/
func (this Aes256Gcm) Update (data []byte) []byte {
    outCount := this.OutLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    C.vscf_aes256_gcm_update(this.ctx, WrapData(data), outBuf)

    return outBuf.GetData() /* r7 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an current mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Gcm) OutLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_gcm_out_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an encryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Gcm) EncryptedOutLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_gcm_encrypted_out_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an decryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Gcm) DecryptedOutLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_gcm_decrypted_out_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Accomplish encryption or decryption process.
*/
func (this Aes256Gcm) Finish () []byte {
    outCount := this.OutLen(0) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_aes256_gcm_finish(this.ctx, outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Defines authentication tag length in bytes.
*/
func (this Aes256Gcm) getAuthTagLen () int32 {
    return 16
}

/*
* Encrypt given data.
* If 'tag' is not given, then it will written to the 'enc'.
*/
func (this Aes256Gcm) AuthEncrypt (data []byte, authData []byte) ([]byte, []byte) {
    outCount := this.AuthEncryptedLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()

    tagCount := this.getAuthTagLen() /* lg3 */
    tagBuf := NewBuffer(tagCount)
    defer tagBuf.Clear()


    proxyResult := C.vscf_aes256_gcm_auth_encrypt(this.ctx, WrapData(data), WrapData(authData), outBuf, tagBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */, tagBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the authenticated encrypted data.
*/
func (this Aes256Gcm) AuthEncryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_gcm_auth_encrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Decrypt given data.
* If 'tag' is not given, then it will be taken from the 'enc'.
*/
func (this Aes256Gcm) AuthDecrypt (data []byte, authData []byte, tag []byte) []byte {
    outCount := this.AuthDecryptedLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_aes256_gcm_auth_decrypt(this.ctx, WrapData(data), WrapData(authData), WrapData(tag), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the authenticated decrypted data.
*/
func (this Aes256Gcm) AuthDecryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_gcm_auth_decrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Set additional data for for AEAD ciphers.
*/
func (this Aes256Gcm) SetAuthData (authData []byte) {
    C.vscf_aes256_gcm_set_auth_data(this.ctx, WrapData(authData))
}

/*
* Accomplish an authenticated encryption and place tag separately.
*
* Note, if authentication tag should be added to an encrypted data,
* method "finish" can be used.
*/
func (this Aes256Gcm) FinishAuthEncryption () ([]byte, []byte) {
    outCount := this.OutLen(0) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()

    tagCount := this.getAuthTagLen() /* lg3 */
    tagBuf := NewBuffer(tagCount)
    defer tagBuf.Clear()


    proxyResult := C.vscf_aes256_gcm_finish_auth_encryption(this.ctx, outBuf, tagBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */, tagBuf.GetData() /* r7 */
}

/*
* Accomplish an authenticated decryption with explicitly given tag.
*
* Note, if authentication tag is a part of an encrypted data then,
* method "finish" can be used for simplicity.
*/
func (this Aes256Gcm) FinishAuthDecryption (tag []byte) []byte {
    outCount := this.OutLen(0) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_aes256_gcm_finish_auth_decryption(this.ctx, WrapData(tag), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
