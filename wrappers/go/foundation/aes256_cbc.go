package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Implementation of the symmetric cipher AES-256 bit in a CBC mode.
* Note, this implementation contains dynamic memory allocations,
* this should be improved in the future releases.
*/
type Aes256Cbc struct {
    IAlg
    IEncrypt
    IDecrypt
    ICipherInfo
    ICipher
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Aes256Cbc) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewAes256Cbc () *Aes256Cbc {
    ctx := C.vscf_aes256_cbc_new()
    return &Aes256Cbc {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAes256CbcWithCtx (ctx *C.vscf_impl_t) *Aes256Cbc {
    return &Aes256Cbc {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAes256CbcCopy (ctx *C.vscf_impl_t) *Aes256Cbc {
    return &Aes256Cbc {
        ctx: C.vscf_aes256_cbc_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Aes256Cbc) AlgId () AlgId {
    proxyResult := C.vscf_aes256_cbc_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Aes256Cbc) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_aes256_cbc_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Aes256Cbc) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_aes256_cbc_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Encrypt given data.
*/
func (this Aes256Cbc) Encrypt (data []byte) []byte {
    outCount := this.EncryptedLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_aes256_cbc_encrypt(this.ctx, WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Aes256Cbc) EncryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_cbc_encrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Precise length calculation of encrypted data.
*/
func (this Aes256Cbc) PreciseEncryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_cbc_precise_encrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Decrypt given data.
*/
func (this Aes256Cbc) Decrypt (data []byte) []byte {
    outCount := this.DecryptedLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_aes256_cbc_decrypt(this.ctx, WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Aes256Cbc) DecryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_cbc_decrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
*/
func (this Aes256Cbc) getNonceLen () int32 {
    return 16
}

/*
* Cipher key length in bytes.
*/
func (this Aes256Cbc) getKeyLen () int32 {
    return 32
}

/*
* Cipher key length in bits.
*/
func (this Aes256Cbc) getKeyBitlen () int32 {
    return 256
}

/*
* Cipher block length in bytes.
*/
func (this Aes256Cbc) getBlockLen () int32 {
    return 16
}

/*
* Setup IV or nonce.
*/
func (this Aes256Cbc) SetNonce (nonce []byte) {
    C.vscf_aes256_cbc_set_nonce(this.ctx, WrapData(nonce))
}

/*
* Set cipher encryption / decryption key.
*/
func (this Aes256Cbc) SetKey (key []byte) {
    C.vscf_aes256_cbc_set_key(this.ctx, WrapData(key))
}

/*
* Start sequential encryption.
*/
func (this Aes256Cbc) StartEncryption () {
    C.vscf_aes256_cbc_start_encryption(this.ctx)
}

/*
* Start sequential decryption.
*/
func (this Aes256Cbc) StartDecryption () {
    C.vscf_aes256_cbc_start_decryption(this.ctx)
}

/*
* Process encryption or decryption of the given data chunk.
*/
func (this Aes256Cbc) Update (data []byte) []byte {
    outCount := this.OutLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    C.vscf_aes256_cbc_update(this.ctx, WrapData(data), outBuf)

    return outBuf.GetData() /* r7 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an current mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Cbc) OutLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_cbc_out_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an encryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Cbc) EncryptedOutLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_cbc_encrypted_out_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an decryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Cbc) DecryptedOutLen (dataLen int32) int32 {
    proxyResult := C.vscf_aes256_cbc_decrypted_out_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Accomplish encryption or decryption process.
*/
func (this Aes256Cbc) Finish () []byte {
    outCount := this.OutLen(0) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_aes256_cbc_finish(this.ctx, outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
