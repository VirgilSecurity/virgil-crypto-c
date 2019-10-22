package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Implements PKCS#8 key serialization to DER format.
*/
type Pkcs8Serializer struct {
    IKeySerializer
    ctx *C.vscf_impl_t
}

func (this Pkcs8Serializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_pkcs8_serializer_release_asn1_writer(this.ctx)
    C.vscf_pkcs8_serializer_use_asn1_writer(this.ctx, asn1Writer.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Pkcs8Serializer) SetupDefaults () {
    C.vscf_pkcs8_serializer_setup_defaults(this.ctx)
}

/*
* Serialize Public Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (this Pkcs8Serializer) SerializePublicKeyInplace (publicKey RawPublicKey) int32 {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_pkcs8_serializer_serialize_public_key_inplace(this.ctx, publicKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return proxyResult //r9
}

/*
* Serialize Private Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (this Pkcs8Serializer) SerializePrivateKeyInplace (privateKey RawPrivateKey) int32 {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_pkcs8_serializer_serialize_private_key_inplace(this.ctx, privateKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return proxyResult //r9
}

/* Handle underlying C context. */
func (this Pkcs8Serializer) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewPkcs8Serializer () *Pkcs8Serializer {
    ctx := C.vscf_pkcs8_serializer_new()
    return &Pkcs8Serializer {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPkcs8SerializerWithCtx (ctx *C.vscf_impl_t) *Pkcs8Serializer {
    return &Pkcs8Serializer {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPkcs8SerializerCopy (ctx *C.vscf_impl_t) *Pkcs8Serializer {
    return &Pkcs8Serializer {
        ctx: C.vscf_pkcs8_serializer_shallow_copy(ctx),
    }
}

/*
* Calculate buffer size enough to hold serialized public key.
*
* Precondition: public key must be exportable.
*/
func (this Pkcs8Serializer) SerializedPublicKeyLen (publicKey RawPublicKey) int32 {
    proxyResult := C.vscf_pkcs8_serializer_serialized_public_key_len(this.ctx, publicKey.Ctx())

    return proxyResult //r9
}

/*
* Serialize given public key to an interchangeable format.
*
* Precondition: public key must be exportable.
*/
func (this Pkcs8Serializer) SerializePublicKey (publicKey RawPublicKey) []byte {
    outCount := this.SerializedPublicKeyLen(publicKey) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_pkcs8_serializer_serialize_public_key(this.ctx, publicKey.Ctx(), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate buffer size enough to hold serialized private key.
*
* Precondition: private key must be exportable.
*/
func (this Pkcs8Serializer) SerializedPrivateKeyLen (privateKey RawPrivateKey) int32 {
    proxyResult := C.vscf_pkcs8_serializer_serialized_private_key_len(this.ctx, privateKey.Ctx())

    return proxyResult //r9
}

/*
* Serialize given private key to an interchangeable format.
*
* Precondition: private key must be exportable.
*/
func (this Pkcs8Serializer) SerializePrivateKey (privateKey RawPrivateKey) []byte {
    outCount := this.SerializedPrivateKeyLen(privateKey) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_pkcs8_serializer_serialize_private_key(this.ctx, privateKey.Ctx(), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
