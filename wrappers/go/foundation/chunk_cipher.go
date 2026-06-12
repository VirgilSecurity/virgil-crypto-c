package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Provides stream encryption in fixed-size chunks, where each encrypted
* chunk carries its own AES-256-GCM authentication tag.
*
* Nonce derivation follows the TLS 1.3 construction:
*     nonce_i = initial_nonce XOR (0x00000000 || uint64_be(i))
*
* Each encrypted frame layout:
*     counter_le64[8] | ciphertext[N] | tag[16]
*
* The initial nonce and chunk size must be stored in the CMS message info
* custom params by the caller; they are not embedded in the ciphertext stream.
*/
type ChunkCipher struct {
    cCtx *C.vscf_chunk_cipher_t
}

/* Handle underlying C context. */
func (obj *ChunkCipher) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewChunkCipher() *ChunkCipher {
    ctx := C.vscf_chunk_cipher_new()
    obj := &ChunkCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChunkCipher).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChunkCipherWithCtx(ctx *C.vscf_chunk_cipher_t) *ChunkCipher {
    obj := &ChunkCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChunkCipher).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChunkCipherCopy(ctx *C.vscf_chunk_cipher_t) *ChunkCipher {
    obj := &ChunkCipher {
        cCtx: C.vscf_chunk_cipher_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*ChunkCipher).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *ChunkCipher) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *ChunkCipher) delete() {
    C.vscf_chunk_cipher_delete(obj.cCtx)
}

func (obj *ChunkCipher) SetRandom(random Random) {
    C.vscf_chunk_cipher_release_random(obj.cCtx)
    C.vscf_chunk_cipher_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Set the 32-byte AES-256 encryption key.
*/
func (obj *ChunkCipher) SetKey(key []byte) {
    keyData := helperWrapData (key)

    C.vscf_chunk_cipher_set_key(obj.cCtx, keyData)

    runtime.KeepAlive(obj)

    return
}

/*
* Set the 12-byte initial nonce for decryption.
* Not needed for encryption: nonce is generated automatically in start_encryption.
*/
func (obj *ChunkCipher) SetNonce(nonce []byte) {
    nonceData := helperWrapData (nonce)

    C.vscf_chunk_cipher_set_nonce(obj.cCtx, nonceData)

    runtime.KeepAlive(obj)

    return
}

/*
* Set the plaintext chunk size in bytes. Default is 65536.
*/
func (obj *ChunkCipher) SetChunkSize(chunkSize uint) {
    C.vscf_chunk_cipher_set_chunk_size(obj.cCtx, (C.size_t)(chunkSize))

    runtime.KeepAlive(obj)

    return
}

/*
* Return the 12-byte initial nonce.
* Valid after calling start_encryption; store in CMS custom params for decryption.
*/
func (obj *ChunkCipher) Nonce() []byte {
    proxyResult := C.vscf_chunk_cipher_nonce(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}

/*
* Return nonce length in bytes (always 12).
*/
func (obj *ChunkCipher) NonceLen() uint {
    proxyResult := C.vscf_chunk_cipher_nonce_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return buffer length required to hold output of process_encryption and finish_encryption.
*/
func (obj *ChunkCipher) EncryptionOutLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_encryption_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Initiate encryption. Generates a random 12-byte initial nonce.
*/
func (obj *ChunkCipher) StartEncryption() error {
    proxyResult := C.vscf_chunk_cipher_start_encryption(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Process encryption of a new portion of data.
*/
func (obj *ChunkCipher) ProcessEncryption(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptionOutLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := C.vscf_chunk_cipher_process_encryption(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Encrypt any remaining pending data and finalize the stream.
*/
func (obj *ChunkCipher) FinishEncryption() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptionOutLen(0)))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := C.vscf_chunk_cipher_finish_encryption(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Return buffer length required to hold output of process_decryption and finish_decryption.
*/
func (obj *ChunkCipher) DecryptionOutLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_decryption_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Initiate decryption. Caller must call set_nonce with the initial nonce from CMS before this.
*/
func (obj *ChunkCipher) StartDecryption() error {
    proxyResult := C.vscf_chunk_cipher_start_decryption(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Process decryption of a new portion of data.
*/
func (obj *ChunkCipher) ProcessDecryption(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptionOutLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := C.vscf_chunk_cipher_process_decryption(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Decrypt any remaining pending data and finalize the stream.
*/
func (obj *ChunkCipher) FinishDecryption() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptionOutLen(0)))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := C.vscf_chunk_cipher_finish_decryption(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}
