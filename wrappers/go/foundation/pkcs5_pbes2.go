package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Virgil Security implementation of the PBES2 (RFC 8018) algorithm.
*/
type Pkcs5Pbes2 struct {
    IAlg
    IEncrypt
    IDecrypt
    ctx *C.vscf_impl_t
}

func (this Pkcs5Pbes2) SetKdf (kdf ISaltedKdf) {
    C.vscf_pkcs5_pbes2_release_kdf(this.ctx)
    C.vscf_pkcs5_pbes2_use_kdf(this.ctx, kdf.Ctx())
}

func (this Pkcs5Pbes2) SetCipher (cipher ICipher) {
    C.vscf_pkcs5_pbes2_release_cipher(this.ctx)
    C.vscf_pkcs5_pbes2_use_cipher(this.ctx, cipher.Ctx())
}

/*
* Configure cipher with a new password.
*/
func (this Pkcs5Pbes2) Reset (pwd []byte) {
    C.vscf_pkcs5_pbes2_reset(this.ctx, WrapData(pwd))
}

/* Handle underlying C context. */
func (this Pkcs5Pbes2) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewPkcs5Pbes2 () *Pkcs5Pbes2 {
    ctx := C.vscf_pkcs5_pbes2_new()
    return &Pkcs5Pbes2 {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPkcs5Pbes2WithCtx (ctx *C.vscf_impl_t) *Pkcs5Pbes2 {
    return &Pkcs5Pbes2 {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPkcs5Pbes2Copy (ctx *C.vscf_impl_t) *Pkcs5Pbes2 {
    return &Pkcs5Pbes2 {
        ctx: C.vscf_pkcs5_pbes2_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Pkcs5Pbes2) AlgId () AlgId {
    proxyResult := C.vscf_pkcs5_pbes2_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Pkcs5Pbes2) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_pkcs5_pbes2_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Pkcs5Pbes2) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_pkcs5_pbes2_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Encrypt given data.
*/
func (this Pkcs5Pbes2) Encrypt (data []byte) []byte {
    outCount := this.EncryptedLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_pkcs5_pbes2_encrypt(this.ctx, WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Pkcs5Pbes2) EncryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_pkcs5_pbes2_encrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Precise length calculation of encrypted data.
*/
func (this Pkcs5Pbes2) PreciseEncryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_pkcs5_pbes2_precise_encrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Decrypt given data.
*/
func (this Pkcs5Pbes2) Decrypt (data []byte) []byte {
    outCount := this.DecryptedLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_pkcs5_pbes2_decrypt(this.ctx, WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Pkcs5Pbes2) DecryptedLen (dataLen int32) int32 {
    proxyResult := C.vscf_pkcs5_pbes2_decrypted_len(this.ctx, dataLen)

    return proxyResult //r9
}
