package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Elliptic curve cryptography implementation.
* Supported curves:
* - secp256r1.
*/
type Ecc struct {
    IAlg
    IKeyAlg
    IKeyCipher
    IKeySigner
    IComputeSharedKey
    cCtx *C.vscf_ecc_t /*ct10*/
}

func (this Ecc) SetRandom (random IRandom) {
    C.vscf_ecc_release_random(this.cCtx)
    C.vscf_ecc_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (this Ecc) SetEcies (ecies Ecies) {
    C.vscf_ecc_release_ecies(this.cCtx)
    C.vscf_ecc_use_ecies(this.cCtx, (*C.vscf_ecies_t)(ecies.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Ecc) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_ecc_setup_defaults(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Generate new private key.
* Supported algorithm ids:
* - secp256r1.
*
* Note, this operation might be slow.
*/
func (this Ecc) GenerateKey (algId AlgId) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ecc_generate_key(this.cCtx, C.vscf_alg_id_t(algId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this Ecc) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewEcc () *Ecc {
    ctx := C.vscf_ecc_new()
    return &Ecc {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccWithCtx (ctx *C.vscf_ecc_t /*ct10*/) *Ecc {
    return &Ecc {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccCopy (ctx *C.vscf_ecc_t /*ct10*/) *Ecc {
    return &Ecc {
        cCtx: C.vscf_ecc_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Ecc) close () {
    C.vscf_ecc_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Ecc) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_ecc_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Ecc) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_ecc_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Ecc) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_ecc_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Defines whether a public key can be imported or not.
*/
func EccGetCanImportPublicKey () bool {
    return true
}

/*
* Define whether a public key can be exported or not.
*/
func EccGetCanExportPublicKey () bool {
    return true
}

/*
* Define whether a private key can be imported or not.
*/
func EccGetCanImportPrivateKey () bool {
    return true
}

/*
* Define whether a private key can be exported or not.
*/
func EccGetCanExportPrivateKey () bool {
    return true
}

/*
* Generate ephemeral private key of the same type.
* Note, this operation might be slow.
*/
func (this Ecc) GenerateEphemeralKey (key IKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ecc_generate_ephemeral_key(this.cCtx, (*C.vscf_impl_t)(key.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Import public key from the raw binary format.
*
* Return public key that is adopted and optimized to be used
* with this particular algorithm.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be imported from the format defined in
* RFC 3447 Appendix A.1.1.
*/
func (this Ecc) ImportPublicKey (rawKey *RawPublicKey) (IPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ecc_import_public_key(this.cCtx, (*C.vscf_raw_public_key_t)(rawKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}

/*
* Export public key to the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA public key must be exported in format defined in
* RFC 3447 Appendix A.1.1.
*/
func (this Ecc) ExportPublicKey (publicKey IPublicKey) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ecc_export_public_key(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPublicKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Import private key from the raw binary format.
*
* Return private key that is adopted and optimized to be used
* with this particular algorithm.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be imported from the format defined in
* RFC 3447 Appendix A.1.2.
*/
func (this Ecc) ImportPrivateKey (rawKey *RawPrivateKey) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ecc_import_private_key(this.cCtx, (*C.vscf_raw_private_key_t)(rawKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Export private key in the raw binary format.
*
* Binary format must be defined in the key specification.
* For instance, RSA private key must be exported in format defined in
* RFC 3447 Appendix A.1.2.
*/
func (this Ecc) ExportPrivateKey (privateKey IPrivateKey) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_ecc_export_private_key(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Check if algorithm can encrypt data with a given key.
*/
func (this Ecc) CanEncrypt (publicKey IPublicKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_ecc_can_encrypt(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (this Ecc) EncryptedLen (publicKey IPublicKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_encrypted_len(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypt data with a given public key.
*/
func (this Ecc) Encrypt (publicKey IPublicKey, data []byte) ([]byte, error) {
    outCount := C.ulong(this.EncryptedLen(publicKey.(IPublicKey), uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_ecc_encrypt(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Check if algorithm can decrypt data with a given key.
* However, success result of decryption is not guaranteed.
*/
func (this Ecc) CanDecrypt (privateKey IPrivateKey, dataLen uint32) bool {
    proxyResult := /*pr4*/C.vscf_ecc_can_decrypt(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return bool(proxyResult) /* r9 */
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (this Ecc) DecryptedLen (privateKey IPrivateKey, dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_decrypted_len(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (this Ecc) Decrypt (privateKey IPrivateKey, data []byte) ([]byte, error) {
    outCount := C.ulong(this.DecryptedLen(privateKey.(IPrivateKey), uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_ecc_decrypt(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Check if algorithm can sign data digest with a given key.
*/
func (this Ecc) CanSign (privateKey IPrivateKey) bool {
    proxyResult := /*pr4*/C.vscf_ecc_can_sign(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Return length in bytes required to hold signature.
* Return zero if a given private key can not produce signatures.
*/
func (this Ecc) SignatureLen (key IKey) uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_signature_len(this.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Sign data digest with a given private key.
*/
func (this Ecc) SignHash (privateKey IPrivateKey, hashId AlgId, digest []byte) ([]byte, error) {
    signatureCount := C.ulong(this.SignatureLen(privateKey.(IKey)) /* lg2 */)
    signatureMemory := make([]byte, int(C.vsc_buffer_ctx_size() + signatureCount))
    signatureBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&signatureMemory[0]))
    signatureData := signatureMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(signatureBuf)
    C.vsc_buffer_use(signatureBuf, (*C.byte)(unsafe.Pointer(&signatureData[0])), signatureCount)
    defer C.vsc_buffer_delete(signatureBuf)
    digestData := C.vsc_data((*C.uint8_t)(&digest[0]), C.size_t(len(digest)))

    proxyResult := /*pr4*/C.vscf_ecc_sign_hash(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return signatureData[0:C.vsc_buffer_len(signatureBuf)] /* r7 */, nil
}

/*
* Check if algorithm can verify data digest with a given key.
*/
func (this Ecc) CanVerify (publicKey IPublicKey) bool {
    proxyResult := /*pr4*/C.vscf_ecc_can_verify(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Verify data digest with a given public key and signature.
*/
func (this Ecc) VerifyHash (publicKey IPublicKey, hashId AlgId, digest []byte, signature []byte) bool {
    digestData := C.vsc_data((*C.uint8_t)(&digest[0]), C.size_t(len(digest)))
    signatureData := C.vsc_data((*C.uint8_t)(&signature[0]), C.size_t(len(signature)))

    proxyResult := /*pr4*/C.vscf_ecc_verify_hash(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), C.vscf_alg_id_t(hashId) /*pa7*/, digestData, signatureData)

    return bool(proxyResult) /* r9 */
}

/*
* Compute shared key for 2 asymmetric keys.
* Note, computed shared key can be used only within symmetric cryptography.
*/
func (this Ecc) ComputeSharedKey (publicKey IPublicKey, privateKey IPrivateKey) ([]byte, error) {
    sharedKeyCount := C.ulong(this.SharedKeyLen(privateKey.(IKey)) /* lg2 */)
    sharedKeyMemory := make([]byte, int(C.vsc_buffer_ctx_size() + sharedKeyCount))
    sharedKeyBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&sharedKeyMemory[0]))
    sharedKeyData := sharedKeyMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(sharedKeyBuf)
    C.vsc_buffer_use(sharedKeyBuf, (*C.byte)(unsafe.Pointer(&sharedKeyData[0])), sharedKeyCount)
    defer C.vsc_buffer_delete(sharedKeyBuf)


    proxyResult := /*pr4*/C.vscf_ecc_compute_shared_key(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), (*C.vscf_impl_t)(privateKey.ctx()), sharedKeyBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return sharedKeyData[0:C.vsc_buffer_len(sharedKeyBuf)] /* r7 */, nil
}

/*
* Return number of bytes required to hold shared key.
* Expect Public Key or Private Key.
*/
func (this Ecc) SharedKeyLen (key IKey) uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_shared_key_len(this.cCtx, (*C.vscf_impl_t)(key.ctx()))

    return uint32(proxyResult) /* r9 */
}
