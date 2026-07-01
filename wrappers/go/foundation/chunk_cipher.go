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

/*
* Return the number of frames the sequential encryption path emits for a plaintext of the
* given length: floor(data_len / chunk_size) + 1. The trailing frame (the one with is_last=true)
* is empty when data_len is an exact multiple of chunk_size. Use this to drive random-access /
* parallel encryption via encrypt_at over indices 0 .. chunk_count-1, placing is_last on the
* highest index. Requires chunk_size to be set (> 0).
*/
func (obj *ChunkCipher) ChunkCount(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_chunk_count(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Encrypt a single chunk at an explicit index for random-access / parallel encryption, writing
* the frame counter_le64[8] | ciphertext | tag[16]. Independent of the start/process/finish
* state machine; requires key, initial nonce, and chunk_size to be set, and the instance to be
* in the INITIAL state (call before, or instead of, start_encryption).
*
* WARNING (nonce safety): each chunk_index must be encrypted at most ONCE per (key, initial_nonce);
* AES-GCM nonce reuse is catastrophic. This API is per-call and does NOT track or enforce
* uniqueness — the caller owns it. Thread-safe: each call uses a per-call local cipher context and
* only reads the instance's key/nonce/chunk_size, so a single configured instance may be used
* concurrently from multiple threads for parallel encryption (no shared mutable cipher state, no
* lock). Whole-file only: the caller must know the total chunk count (see chunk_count) to place
* exactly one is_last frame.
*/
func (obj *ChunkCipher) EncryptAt(chunkIndex uint64, isLast bool, plaintext []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptionOutLen(uint(len(plaintext)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    plaintextData := helperWrapData (plaintext)

    proxyResult := C.vscf_chunk_cipher_encrypt_at(obj.cCtx, (C.uint64_t)(chunkIndex), (C.bool)(isLast), plaintextData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Authenticate and decrypt a single frame as an explicit chunk index for random-access reads.
* The frame's embedded counter is validated against the passed-in chunk_index (a mismatch returns
* ERROR_BAD_ENCRYPTED_DATA), so callers must pass the true positional index and never trust the
* frame's own counter. Independent of the streaming state machine; requires key, initial nonce,
* and chunk_size to be set, and the instance to be in the INITIAL state.
*
* Thread-safe: uses a per-call local cipher context and only reads the instance's
* key/nonce/chunk_size, so a single configured instance may be used concurrently from multiple
* threads for parallel/random-access decryption (no shared mutable cipher state, no lock). Note:
* this authenticates which frame is last (is_last) and each frame's position, but not the total
* number of frames — protect against truncation by authenticating the chunk count out of band
* (or deriving it from the ciphertext length).
*/
func (obj *ChunkCipher) DecryptAt(chunkIndex uint64, isLast bool, frame []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptionOutLen(uint(len(frame)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    frameData := helperWrapData (frame)

    proxyResult := C.vscf_chunk_cipher_decrypt_at(obj.cCtx, (C.uint64_t)(chunkIndex), (C.bool)(isLast), frameData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}
