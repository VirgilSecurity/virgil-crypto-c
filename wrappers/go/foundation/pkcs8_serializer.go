package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Implements PKCS#8 key serialization to DER format.
*/
type Pkcs8Serializer struct {
    IKeySerializer
    cCtx *C.vscf_pkcs8_serializer_t /*ct10*/
}

func (this Pkcs8Serializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_pkcs8_serializer_release_asn1_writer(this.cCtx)
    C.vscf_pkcs8_serializer_use_asn1_writer(this.cCtx, (*C.vscf_impl_t)(asn1Writer.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Pkcs8Serializer) SetupDefaults () {
    C.vscf_pkcs8_serializer_setup_defaults(this.cCtx)

    return
}

/*
* Serialize Public Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (this Pkcs8Serializer) SerializePublicKeyInplace (publicKey *RawPublicKey) (uint32, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_pkcs8_serializer_serialize_public_key_inplace(this.cCtx, (*C.vscf_raw_public_key_t)(publicKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return 0, err
    }

    return uint32(proxyResult) /* r9 */, nil
}

/*
* Serialize Private Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (this Pkcs8Serializer) SerializePrivateKeyInplace (privateKey *RawPrivateKey) (uint32, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_pkcs8_serializer_serialize_private_key_inplace(this.cCtx, (*C.vscf_raw_private_key_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return 0, err
    }

    return uint32(proxyResult) /* r9 */, nil
}

/* Handle underlying C context. */
func (this Pkcs8Serializer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewPkcs8Serializer () *Pkcs8Serializer {
    ctx := C.vscf_pkcs8_serializer_new()
    return &Pkcs8Serializer {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPkcs8SerializerWithCtx (ctx *C.vscf_pkcs8_serializer_t /*ct10*/) *Pkcs8Serializer {
    return &Pkcs8Serializer {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPkcs8SerializerCopy (ctx *C.vscf_pkcs8_serializer_t /*ct10*/) *Pkcs8Serializer {
    return &Pkcs8Serializer {
        cCtx: C.vscf_pkcs8_serializer_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Pkcs8Serializer) close () {
    C.vscf_pkcs8_serializer_delete(this.cCtx)
}

/*
* Calculate buffer size enough to hold serialized public key.
*
* Precondition: public key must be exportable.
*/
func (this Pkcs8Serializer) SerializedPublicKeyLen (publicKey *RawPublicKey) uint32 {
    proxyResult := /*pr4*/C.vscf_pkcs8_serializer_serialized_public_key_len(this.cCtx, (*C.vscf_raw_public_key_t)(publicKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize given public key to an interchangeable format.
*
* Precondition: public key must be exportable.
*/
func (this Pkcs8Serializer) SerializePublicKey (publicKey *RawPublicKey) ([]byte, error) {
    outCount := C.ulong(this.SerializedPublicKeyLen(publicKey) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_pkcs8_serializer_serialize_public_key(this.cCtx, (*C.vscf_raw_public_key_t)(publicKey.ctx()), outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Calculate buffer size enough to hold serialized private key.
*
* Precondition: private key must be exportable.
*/
func (this Pkcs8Serializer) SerializedPrivateKeyLen (privateKey *RawPrivateKey) uint32 {
    proxyResult := /*pr4*/C.vscf_pkcs8_serializer_serialized_private_key_len(this.cCtx, (*C.vscf_raw_private_key_t)(privateKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize given private key to an interchangeable format.
*
* Precondition: private key must be exportable.
*/
func (this Pkcs8Serializer) SerializePrivateKey (privateKey *RawPrivateKey) ([]byte, error) {
    outCount := C.ulong(this.SerializedPrivateKeyLen(privateKey) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_pkcs8_serializer_serialize_private_key(this.cCtx, (*C.vscf_raw_private_key_t)(privateKey.ctx()), outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}
