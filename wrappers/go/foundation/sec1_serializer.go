package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Implements SEC 1 key serialization to DER format.
* See also RFC 5480 and RFC 5915.
*/
type Sec1Serializer struct {
    IKeySerializer
    ctx *C.vscf_impl_t
}

func (this Sec1Serializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_sec1_serializer_release_asn1_writer(this.ctx)
    C.vscf_sec1_serializer_use_asn1_writer(this.ctx, asn1Writer.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Sec1Serializer) SetupDefaults () {
    C.vscf_sec1_serializer_setup_defaults(this.ctx)
}

/*
* Serialize Public Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (this Sec1Serializer) SerializePublicKeyInplace (publicKey RawPublicKey) int32 {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_sec1_serializer_serialize_public_key_inplace(this.ctx, publicKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return proxyResult //r9
}

/*
* Serialize Private Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (this Sec1Serializer) SerializePrivateKeyInplace (privateKey RawPrivateKey) int32 {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_sec1_serializer_serialize_private_key_inplace(this.ctx, privateKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return proxyResult //r9
}

/* Handle underlying C context. */
func (this Sec1Serializer) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSec1Serializer () *Sec1Serializer {
    ctx := C.vscf_sec1_serializer_new()
    return &Sec1Serializer {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSec1SerializerWithCtx (ctx *C.vscf_impl_t) *Sec1Serializer {
    return &Sec1Serializer {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSec1SerializerCopy (ctx *C.vscf_impl_t) *Sec1Serializer {
    return &Sec1Serializer {
        ctx: C.vscf_sec1_serializer_shallow_copy(ctx),
    }
}

/*
* Calculate buffer size enough to hold serialized public key.
*
* Precondition: public key must be exportable.
*/
func (this Sec1Serializer) SerializedPublicKeyLen (publicKey RawPublicKey) int32 {
    proxyResult := C.vscf_sec1_serializer_serialized_public_key_len(this.ctx, publicKey.Ctx())

    return proxyResult //r9
}

/*
* Serialize given public key to an interchangeable format.
*
* Precondition: public key must be exportable.
*/
func (this Sec1Serializer) SerializePublicKey (publicKey RawPublicKey) []byte {
    outCount := this.SerializedPublicKeyLen(publicKey) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_sec1_serializer_serialize_public_key(this.ctx, publicKey.Ctx(), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate buffer size enough to hold serialized private key.
*
* Precondition: private key must be exportable.
*/
func (this Sec1Serializer) SerializedPrivateKeyLen (privateKey RawPrivateKey) int32 {
    proxyResult := C.vscf_sec1_serializer_serialized_private_key_len(this.ctx, privateKey.Ctx())

    return proxyResult //r9
}

/*
* Serialize given private key to an interchangeable format.
*
* Precondition: private key must be exportable.
*/
func (this Sec1Serializer) SerializePrivateKey (privateKey RawPrivateKey) []byte {
    outCount := this.SerializedPrivateKeyLen(privateKey) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_sec1_serializer_serialize_private_key(this.ctx, privateKey.Ctx(), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
