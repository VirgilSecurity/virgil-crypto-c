package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Virgil implementation of the ECIES algorithm.
*/
type Ecies struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Ecies) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewEcies () *Ecies {
    ctx := C.vscf_ecies_new()
    return &Ecies {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEciesWithCtx (ctx *C.vscf_impl_t) *Ecies {
    return &Ecies {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEciesCopy (ctx *C.vscf_impl_t) *Ecies {
    return &Ecies {
        ctx: C.vscf_ecies_shallow_copy(ctx),
    }
}

func (this Ecies) SetRandom (random IRandom) {
    C.vscf_ecies_release_random(this.ctx)
    C.vscf_ecies_use_random(this.ctx, random.Ctx())
}

func (this Ecies) SetCipher (cipher ICipher) {
    C.vscf_ecies_release_cipher(this.ctx)
    C.vscf_ecies_use_cipher(this.ctx, cipher.Ctx())
}

func (this Ecies) SetMac (mac IMac) {
    C.vscf_ecies_release_mac(this.ctx)
    C.vscf_ecies_use_mac(this.ctx, mac.Ctx())
}

func (this Ecies) SetKdf (kdf IKdf) {
    C.vscf_ecies_release_kdf(this.ctx)
    C.vscf_ecies_use_kdf(this.ctx, kdf.Ctx())
}

/*
* Set ephemeral key that used for data encryption.
* Public and ephemeral keys should belong to the same curve.
* This dependency is optional.
*/
func (this Ecies) SetEphemeralKey (ephemeralKey IPrivateKey) {
    C.vscf_ecies_release_ephemeral_key(this.ctx)
    C.vscf_ecies_use_ephemeral_key(this.ctx, ephemeralKey.Ctx())
}

/*
* Set weak reference to the key algorithm.
* Key algorithm MUST support shared key computation as well.
*/
func (this Ecies) SetKeyAlg (keyAlg IKeyAlg) {
    C.vscf_ecies_set_key_alg(this.ctx, keyAlg.Ctx())
}

/*
* Release weak reference to the key algorithm.
*/
func (this Ecies) ReleaseKeyAlg () {
    C.vscf_ecies_release_key_alg(this.ctx)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Ecies) SetupDefaults () {
    proxyResult := C.vscf_ecies_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Setup predefined values to the uninitialized class dependencies
* except random.
*/
func (this Ecies) SetupDefaultsNoRandom () {
    C.vscf_ecies_setup_defaults_no_random(this.ctx)
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Ecies) EncryptedLen (publicKey IPublicKey, dataLen int32) int32 {
    proxyResult := C.vscf_ecies_encrypted_len(this.ctx, publicKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Encrypt data with a given public key.
*/
func (this Ecies) Encrypt (publicKey IPublicKey, data []byte) []byte {
    outCount := this.EncryptedLen(publicKey, int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_ecies_encrypt(this.ctx, publicKey.Ctx(), WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Ecies) DecryptedLen (privateKey IPrivateKey, dataLen int32) int32 {
    proxyResult := C.vscf_ecies_decrypted_len(this.ctx, privateKey.Ctx(), dataLen)

    return proxyResult //r9
}

/*
* Decrypt given data.
*/
func (this Ecies) Decrypt (privateKey IPrivateKey, data []byte) []byte {
    outCount := this.DecryptedLen(privateKey, int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_ecies_decrypt(this.ctx, privateKey.Ctx(), WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
