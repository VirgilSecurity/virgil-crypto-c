package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Virgil implementation of the ECIES algorithm.
*/
type Ecies struct {
    cCtx *C.vscf_ecies_t /*ct2*/
}

/* Handle underlying C context. */
func (this Ecies) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewEcies () *Ecies {
    ctx := C.vscf_ecies_new()
    return &Ecies {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEciesWithCtx (ctx *C.vscf_ecies_t /*ct2*/) *Ecies {
    return &Ecies {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEciesCopy (ctx *C.vscf_ecies_t /*ct2*/) *Ecies {
    return &Ecies {
        cCtx: C.vscf_ecies_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Ecies) close () {
    C.vscf_ecies_delete(this.cCtx)
}

func (this Ecies) SetRandom (random IRandom) {
    C.vscf_ecies_release_random(this.cCtx)
    C.vscf_ecies_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (this Ecies) SetCipher (cipher ICipher) {
    C.vscf_ecies_release_cipher(this.cCtx)
    C.vscf_ecies_use_cipher(this.cCtx, (*C.vscf_impl_t)(cipher.ctx()))
}

func (this Ecies) SetMac (mac IMac) {
    C.vscf_ecies_release_mac(this.cCtx)
    C.vscf_ecies_use_mac(this.cCtx, (*C.vscf_impl_t)(mac.ctx()))
}

func (this Ecies) SetKdf (kdf IKdf) {
    C.vscf_ecies_release_kdf(this.cCtx)
    C.vscf_ecies_use_kdf(this.cCtx, (*C.vscf_impl_t)(kdf.ctx()))
}

/*
* Set ephemeral key that used for data encryption.
* Public and ephemeral keys should belong to the same curve.
* This dependency is optional.
*/
func (this Ecies) SetEphemeralKey (ephemeralKey IPrivateKey) {
    C.vscf_ecies_release_ephemeral_key(this.cCtx)
    C.vscf_ecies_use_ephemeral_key(this.cCtx, (*C.vscf_impl_t)(ephemeralKey.ctx()))
}

/*
* Set weak reference to the key algorithm.
* Key algorithm MUST support shared key computation as well.
*/
func (this Ecies) SetKeyAlg (keyAlg IKeyAlg) {
    C.vscf_ecies_set_key_alg(this.cCtx, (*C.vscf_impl_t)(keyAlg.ctx()))

    return
}

/*
* Release weak reference to the key algorithm.
*/
func (this Ecies) ReleaseKeyAlg () {
    C.vscf_ecies_release_key_alg(this.cCtx)

    return
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Ecies) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_ecies_setup_defaults(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Setup predefined values to the uninitialized class dependencies
* except random.
*/
func (this Ecies) SetupDefaultsNoRandom () {
    C.vscf_ecies_setup_defaults_no_random(this.cCtx)

    return
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Ecies) EncryptedLen (publicKey IPublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ecies_encrypted_len(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (this Ecies) Encrypt (publicKey IPublicKey, data []byte) ([]byte, error) {
    outCount := C.ulong(this.EncryptedLen(publicKey.(IPublicKey), uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_ecies_encrypt(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Ecies) DecryptedLen (privateKey IPrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ecies_decrypted_len(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (this Ecies) Decrypt (privateKey IPrivateKey, data []byte) ([]byte, error) {
    outCount := C.ulong(this.DecryptedLen(privateKey.(IPrivateKey), uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_ecies_decrypt(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}
