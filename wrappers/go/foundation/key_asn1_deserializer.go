package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Implements PKCS#8 and SEC1 key deserialization from DER / PEM format.
*/
type KeyAsn1Deserializer struct {
    IKeyDeserializer
    cCtx *C.vscf_key_asn1_deserializer_t /*ct10*/
}

func (this KeyAsn1Deserializer) SetAsn1Reader (asn1Reader IAsn1Reader) {
    C.vscf_key_asn1_deserializer_release_asn1_reader(this.cCtx)
    C.vscf_key_asn1_deserializer_use_asn1_reader(this.cCtx, (*C.vscf_impl_t)(asn1Reader.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this KeyAsn1Deserializer) SetupDefaults () {
    C.vscf_key_asn1_deserializer_setup_defaults(this.cCtx)

    return
}

/*
* Deserialize Public Key by using internal ASN.1 reader.
* Note, that caller code is responsible to reset ASN.1 reader with
* an input buffer.
*/
func (this KeyAsn1Deserializer) DeserializePublicKeyInplace () (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_asn1_deserializer_deserialize_public_key_inplace(this.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPublicKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Deserialize Private Key by using internal ASN.1 reader.
* Note, that caller code is responsible to reset ASN.1 reader with
* an input buffer.
*/
func (this KeyAsn1Deserializer) DeserializePrivateKeyInplace () (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_asn1_deserializer_deserialize_private_key_inplace(this.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/* Handle underlying C context. */
func (this KeyAsn1Deserializer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewKeyAsn1Deserializer () *KeyAsn1Deserializer {
    ctx := C.vscf_key_asn1_deserializer_new()
    return &KeyAsn1Deserializer {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyAsn1DeserializerWithCtx (ctx *C.vscf_key_asn1_deserializer_t /*ct10*/) *KeyAsn1Deserializer {
    return &KeyAsn1Deserializer {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyAsn1DeserializerCopy (ctx *C.vscf_key_asn1_deserializer_t /*ct10*/) *KeyAsn1Deserializer {
    return &KeyAsn1Deserializer {
        cCtx: C.vscf_key_asn1_deserializer_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this KeyAsn1Deserializer) close () {
    C.vscf_key_asn1_deserializer_delete(this.cCtx)
}

/*
* Deserialize given public key as an interchangeable format to the object.
*/
func (this KeyAsn1Deserializer) DeserializePublicKey (publicKeyData []byte) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    publicKeyDataData := C.vsc_data((*C.uint8_t)(&publicKeyData[0]), C.size_t(len(publicKeyData)))

    proxyResult := /*pr4*/C.vscf_key_asn1_deserializer_deserialize_public_key(this.cCtx, publicKeyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPublicKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Deserialize given private key as an interchangeable format to the object.
*/
func (this KeyAsn1Deserializer) DeserializePrivateKey (privateKeyData []byte) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    privateKeyDataData := C.vsc_data((*C.uint8_t)(&privateKeyData[0]), C.size_t(len(privateKeyData)))

    proxyResult := /*pr4*/C.vscf_key_asn1_deserializer_deserialize_private_key(this.cCtx, privateKeyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}
