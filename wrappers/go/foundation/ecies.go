package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Virgil implementation of the ECIES algorithm.
*/
type Ecies struct {
    cCtx *C.vscf_ecies_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *Ecies) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewEcies() *Ecies {
    ctx := C.vscf_ecies_new()
    obj := &Ecies {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Ecies).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEciesWithCtx(ctx *C.vscf_ecies_t /*ct2*/) *Ecies {
    obj := &Ecies {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Ecies).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEciesCopy(ctx *C.vscf_ecies_t /*ct2*/) *Ecies {
    obj := &Ecies {
        cCtx: C.vscf_ecies_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Ecies).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Ecies) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Ecies) delete() {
    C.vscf_ecies_delete(obj.cCtx)
}

func (obj *Ecies) SetRandom(random Random) {
    C.vscf_ecies_release_random(obj.cCtx)
    C.vscf_ecies_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *Ecies) SetCipher(cipher Cipher) {
    C.vscf_ecies_release_cipher(obj.cCtx)
    C.vscf_ecies_use_cipher(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(cipher.Ctx())))

    runtime.KeepAlive(cipher)
    runtime.KeepAlive(obj)
}

func (obj *Ecies) SetMac(mac Mac) {
    C.vscf_ecies_release_mac(obj.cCtx)
    C.vscf_ecies_use_mac(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(mac.Ctx())))

    runtime.KeepAlive(mac)
    runtime.KeepAlive(obj)
}

func (obj *Ecies) SetKdf(kdf Kdf) {
    C.vscf_ecies_release_kdf(obj.cCtx)
    C.vscf_ecies_use_kdf(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(kdf.Ctx())))

    runtime.KeepAlive(kdf)
    runtime.KeepAlive(obj)
}

/*
* Set ephemeral key that used for data encryption.
* Public and ephemeral keys should belong to the same curve.
* This dependency is optional.
*/
func (obj *Ecies) SetEphemeralKey(ephemeralKey PrivateKey) {
    C.vscf_ecies_release_ephemeral_key(obj.cCtx)
    C.vscf_ecies_use_ephemeral_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(ephemeralKey.Ctx())))

    runtime.KeepAlive(ephemeralKey)
    runtime.KeepAlive(obj)
}

/*
* Set weak reference to the key algorithm.
* Key algorithm MUST support shared key computation as well.
*/
func (obj *Ecies) SetKeyAlg(keyAlg KeyAlg) {
    C.vscf_ecies_set_key_alg(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(keyAlg.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(keyAlg)

    return
}

/*
* Release weak reference to the key algorithm.
*/
func (obj *Ecies) ReleaseKeyAlg() {
    C.vscf_ecies_release_key_alg(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Ecies) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_ecies_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Setup predefined values to the uninitialized class dependencies
* except random.
*/
func (obj *Ecies) SetupDefaultsNoRandom() {
    C.vscf_ecies_setup_defaults_no_random(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Ecies) EncryptedLen(publicKey PublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ecies_encrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (obj *Ecies) Encrypt(publicKey PublicKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(publicKey.(PublicKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_ecies_encrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Ecies) DecryptedLen(privateKey PrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ecies_decrypted_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Ecies) Decrypt(privateKey PrivateKey, data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(privateKey.(PrivateKey), uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_ecies_decrypt(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return outBuf.getData() /* r7 */, nil
}
