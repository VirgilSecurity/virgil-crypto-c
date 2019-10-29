package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

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
    cCtx *C.vscf_aes256_cbc_t /*ct10*/
}

/* Handle underlying C context. */
func (this Aes256Cbc) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewAes256Cbc () *Aes256Cbc {
    ctx := C.vscf_aes256_cbc_new()
    return &Aes256Cbc {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAes256CbcWithCtx (ctx *C.vscf_aes256_cbc_t /*ct10*/) *Aes256Cbc {
    return &Aes256Cbc {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAes256CbcCopy (ctx *C.vscf_aes256_cbc_t /*ct10*/) *Aes256Cbc {
    return &Aes256Cbc {
        cCtx: C.vscf_aes256_cbc_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Aes256Cbc) close () {
    C.vscf_aes256_cbc_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Aes256Cbc) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Aes256Cbc) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Aes256Cbc) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Encrypt given data.
*/
func (this Aes256Cbc) Encrypt (data []byte) ([]byte, error) {
    outCount := C.ulong(this.EncryptedLen(uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_aes256_cbc_encrypt(this.cCtx, dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Aes256Cbc) EncryptedLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_encrypted_len(this.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Precise length calculation of encrypted data.
*/
func (this Aes256Cbc) PreciseEncryptedLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_precise_encrypted_len(this.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (this Aes256Cbc) Decrypt (data []byte) ([]byte, error) {
    outCount := C.ulong(this.DecryptedLen(uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_aes256_cbc_decrypt(this.cCtx, dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Aes256Cbc) DecryptedLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_decrypted_len(this.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
*/
func Aes256CbcGetNonceLen () uint32 {
    return 16
}

/*
* Cipher key length in bytes.
*/
func Aes256CbcGetKeyLen () uint32 {
    return 32
}

/*
* Cipher key length in bits.
*/
func Aes256CbcGetKeyBitlen () uint32 {
    return 256
}

/*
* Cipher block length in bytes.
*/
func Aes256CbcGetBlockLen () uint32 {
    return 16
}

/*
* Setup IV or nonce.
*/
func (this Aes256Cbc) SetNonce (nonce []byte) {
    nonceData := C.vsc_data((*C.uint8_t)(&nonce[0]), C.size_t(len(nonce)))

    C.vscf_aes256_cbc_set_nonce(this.cCtx, nonceData)

    return
}

/*
* Set cipher encryption / decryption key.
*/
func (this Aes256Cbc) SetKey (key []byte) {
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))

    C.vscf_aes256_cbc_set_key(this.cCtx, keyData)

    return
}

/*
* Start sequential encryption.
*/
func (this Aes256Cbc) StartEncryption () {
    C.vscf_aes256_cbc_start_encryption(this.cCtx)

    return
}

/*
* Start sequential decryption.
*/
func (this Aes256Cbc) StartDecryption () {
    C.vscf_aes256_cbc_start_decryption(this.cCtx)

    return
}

/*
* Process encryption or decryption of the given data chunk.
*/
func (this Aes256Cbc) Update (data []byte) []byte {
    outCount := C.ulong(this.OutLen(uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_aes256_cbc_update(this.cCtx, dataData, outBuf)

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an current mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Cbc) OutLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_out_len(this.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an encryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Cbc) EncryptedOutLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_encrypted_out_len(this.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an decryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (this Aes256Cbc) DecryptedOutLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_decrypted_out_len(this.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Accomplish encryption or decryption process.
*/
func (this Aes256Cbc) Finish () ([]byte, error) {
    outCount := C.ulong(this.OutLen(0) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_aes256_cbc_finish(this.cCtx, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}
