package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Virgil implementation of the ECIES algorithm.
*/
type Ecies struct {
    cCtx *C.vscf_ecies_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *Ecies) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
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

/*
* Release underlying C context.
*/
func (obj *Ecies) Delete () {
    C.vscf_ecies_delete(obj.cCtx)
}

func (obj *Ecies) SetRandom (random IRandom) {
    C.vscf_ecies_release_random(obj.cCtx)
    C.vscf_ecies_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (obj *Ecies) SetCipher (cipher ICipher) {
    C.vscf_ecies_release_cipher(obj.cCtx)
    C.vscf_ecies_use_cipher(obj.cCtx, (*C.vscf_impl_t)(cipher.ctx()))
}

func (obj *Ecies) SetMac (mac IMac) {
    C.vscf_ecies_release_mac(obj.cCtx)
    C.vscf_ecies_use_mac(obj.cCtx, (*C.vscf_impl_t)(mac.ctx()))
}

func (obj *Ecies) SetKdf (kdf IKdf) {
    C.vscf_ecies_release_kdf(obj.cCtx)
    C.vscf_ecies_use_kdf(obj.cCtx, (*C.vscf_impl_t)(kdf.ctx()))
}

/*
* Set ephemeral key that used for data encryption.
* Public and ephemeral keys should belong to the same curve.
* This dependency is optional.
*/
func (obj *Ecies) SetEphemeralKey (ephemeralKey IPrivateKey) {
    C.vscf_ecies_release_ephemeral_key(obj.cCtx)
    C.vscf_ecies_use_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(ephemeralKey.ctx()))
}

/*
* Set weak reference to the key algorithm.
* Key algorithm MUST support shared key computation as well.
*/
func (obj *Ecies) SetKeyAlg (keyAlg IKeyAlg) {
    C.vscf_ecies_set_key_alg(obj.cCtx, (*C.vscf_impl_t)(keyAlg.ctx()))

    return
}

/*
* Release weak reference to the key algorithm.
*/
func (obj *Ecies) ReleaseKeyAlg () {
    C.vscf_ecies_release_key_alg(obj.cCtx)

    return
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Ecies) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_ecies_setup_defaults(obj.cCtx)

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
func (obj *Ecies) SetupDefaultsNoRandom () {
    C.vscf_ecies_setup_defaults_no_random(obj.cCtx)

    return
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Ecies) EncryptedLen (publicKey IPublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ecies_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *Ecies) Encrypt (publicKey IPublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(IPublicKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_ecies_encrypt(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Ecies) DecryptedLen (privateKey IPrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ecies_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Ecies) Decrypt (privateKey IPrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(IPrivateKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_ecies_decrypt(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}
