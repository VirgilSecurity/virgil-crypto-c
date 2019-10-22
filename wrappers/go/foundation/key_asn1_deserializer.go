package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Implements PKCS#8 and SEC1 key deserialization from DER / PEM format.
*/
type KeyAsn1Deserializer struct {
    IKeyDeserializer
    ctx *C.vscf_impl_t
}

func (this KeyAsn1Deserializer) SetAsn1Reader (asn1Reader IAsn1Reader) {
    C.vscf_key_asn1_deserializer_release_asn1_reader(this.ctx)
    C.vscf_key_asn1_deserializer_use_asn1_reader(this.ctx, asn1Reader.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this KeyAsn1Deserializer) SetupDefaults () {
    C.vscf_key_asn1_deserializer_setup_defaults(this.ctx)
}

/*
* Deserialize Public Key by using internal ASN.1 reader.
* Note, that caller code is responsible to reset ASN.1 reader with
* an input buffer.
*/
func (this KeyAsn1Deserializer) DeserializePublicKeyInplace () RawPublicKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_asn1_deserializer_deserialize_public_key_inplace(this.ctx, &error)

    FoundationErrorHandleStatus(error.status)

    return *NewRawPublicKeyWithCtx(proxyResult) /* r6 */
}

/*
* Deserialize Private Key by using internal ASN.1 reader.
* Note, that caller code is responsible to reset ASN.1 reader with
* an input buffer.
*/
func (this KeyAsn1Deserializer) DeserializePrivateKeyInplace () RawPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_asn1_deserializer_deserialize_private_key_inplace(this.ctx, &error)

    FoundationErrorHandleStatus(error.status)

    return *NewRawPrivateKeyWithCtx(proxyResult) /* r6 */
}

/* Handle underlying C context. */
func (this KeyAsn1Deserializer) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewKeyAsn1Deserializer () *KeyAsn1Deserializer {
    ctx := C.vscf_key_asn1_deserializer_new()
    return &KeyAsn1Deserializer {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyAsn1DeserializerWithCtx (ctx *C.vscf_impl_t) *KeyAsn1Deserializer {
    return &KeyAsn1Deserializer {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyAsn1DeserializerCopy (ctx *C.vscf_impl_t) *KeyAsn1Deserializer {
    return &KeyAsn1Deserializer {
        ctx: C.vscf_key_asn1_deserializer_shallow_copy(ctx),
    }
}

/*
* Deserialize given public key as an interchangeable format to the object.
*/
func (this KeyAsn1Deserializer) DeserializePublicKey (publicKeyData []byte) RawPublicKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_asn1_deserializer_deserialize_public_key(this.ctx, WrapData(publicKeyData), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewRawPublicKeyWithCtx(proxyResult) /* r6 */
}

/*
* Deserialize given private key as an interchangeable format to the object.
*/
func (this KeyAsn1Deserializer) DeserializePrivateKey (privateKeyData []byte) RawPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_asn1_deserializer_deserialize_private_key(this.ctx, WrapData(privateKeyData), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewRawPrivateKeyWithCtx(proxyResult) /* r6 */
}
