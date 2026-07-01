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
* The construction is self-describing: it produces and restores a
* 'chunked alg info' (algorithm id 'aes256 gcm chunked' carrying version,
* chunk size, and the initial nonce) via the 'alg' interface, so the
* generic decryptor (recipient cipher / alg factory) can reconstruct and
* drive it through the 'cipher' interface without out-of-band parameters.
*/
type ChunkCipher struct {
    cCtx *C.vscf_chunk_cipher_t
}

func (obj *ChunkCipher) SetRandom(random Random) {
    C.vscf_chunk_cipher_release_random(obj.cCtx)
    C.vscf_chunk_cipher_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
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

/*
* Set the 12-byte initial nonce. On encryption this is honored (not
* regenerated) by start_encryption; on decryption it is required.
*/
func (obj *ChunkCipher) SetNonce(nonce []byte) {
    nonceData := helperWrapData (nonce)

    C.vscf_chunk_cipher_set_nonce(obj.cCtx, nonceData)

    runtime.KeepAlive(obj)

    return
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
* Initiate encryption. Generates a random 12-byte initial nonce only if
* one was not already set (via set_nonce or restore_alg_info), so an
* injected nonce is honored. An RNG failure is captured and surfaced
* from the first process_encryption/update/finish call.
*/
func (obj *ChunkCipher) StartEncryption() {
    C.vscf_chunk_cipher_start_encryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Initiate decryption. Caller must set the initial nonce (via set_nonce
* or restore_alg_info) before this.
*/
func (obj *ChunkCipher) StartDecryption() {
    C.vscf_chunk_cipher_start_decryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Process encryption or decryption of the given data chunk.
* Dispatches to the framed encryption or decryption path depending on
* the current state.
*/
func (obj *ChunkCipher) Update(data []byte) []byte {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(uint(len(data)))))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_chunk_cipher_update(obj.cCtx, dataData, outBuf.ctx)

    runtime.KeepAlive(obj)

    return outBuf.getData()
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an current mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *ChunkCipher) OutLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an encryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *ChunkCipher) EncryptedOutLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_encrypted_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an decryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *ChunkCipher) DecryptedOutLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_decrypted_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Accomplish encryption or decryption process.
* Dispatches to finish_encryption or finish_decryption depending on
* the current state.
*/
func (obj *ChunkCipher) Finish() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(0)))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := C.vscf_chunk_cipher_finish(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
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

/*
* Provide algorithm identificator.
*/
func (obj *ChunkCipher) AlgId() AlgId {
    proxyResult := C.vscf_chunk_cipher_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *ChunkCipher) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_chunk_cipher_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult)
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *ChunkCipher) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := C.vscf_chunk_cipher_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return nil
}

/*
* Encrypt given data.
*/
func (obj *ChunkCipher) Encrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptedLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := C.vscf_chunk_cipher_encrypt(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *ChunkCipher) EncryptedLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_encrypted_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Precise length calculation of encrypted data.
*/
func (obj *ChunkCipher) PreciseEncryptedLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_precise_encrypted_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Decrypt given data.
*/
func (obj *ChunkCipher) Decrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptedLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := C.vscf_chunk_cipher_decrypt(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *ChunkCipher) DecryptedLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_decrypted_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
*/
func (obj *ChunkCipher) GetNonceLen() uint {
    return 12
}

/*
* Cipher key length in bytes.
*/
func (obj *ChunkCipher) GetKeyLen() uint {
    return 32
}

/*
* Cipher key length in bits.
*/
func (obj *ChunkCipher) GetKeyBitlen() uint {
    return 256
}

/*
* Cipher block length in bytes.
*/
func (obj *ChunkCipher) GetBlockLen() uint {
    return 16
}

/*
* Setup IV or nonce.
*/
func (obj *ChunkCipher) SetNonce(nonce []byte) {
    nonceData := helperWrapData (nonce)

    C.vscf_chunk_cipher_set_nonce(obj.cCtx, nonceData)

    runtime.KeepAlive(obj)

    return
}

/*
* Set cipher encryption / decryption key.
*/
func (obj *ChunkCipher) SetKey(key []byte) {
    keyData := helperWrapData (key)

    C.vscf_chunk_cipher_set_key(obj.cCtx, keyData)

    runtime.KeepAlive(obj)

    return
}

/*
* Start sequential encryption.
*/
func (obj *ChunkCipher) StartEncryption() {
    C.vscf_chunk_cipher_start_encryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Start sequential decryption.
*/
func (obj *ChunkCipher) StartDecryption() {
    C.vscf_chunk_cipher_start_decryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Process encryption or decryption of the given data chunk.
*/
func (obj *ChunkCipher) Update(data []byte) []byte {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(uint(len(data)))))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_chunk_cipher_update(obj.cCtx, dataData, outBuf.ctx)

    runtime.KeepAlive(obj)

    return outBuf.getData()
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an current mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *ChunkCipher) OutLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an encryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *ChunkCipher) EncryptedOutLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_encrypted_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an decryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *ChunkCipher) DecryptedOutLen(dataLen uint) uint {
    proxyResult := C.vscf_chunk_cipher_decrypted_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Accomplish encryption or decryption process.
*/
func (obj *ChunkCipher) Finish() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(0)))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := C.vscf_chunk_cipher_finish(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}
