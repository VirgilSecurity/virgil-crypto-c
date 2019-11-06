package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Implements key serialization in the ASN.1 format (DER / PEM):
* - SEC1 - for EC private keys;
* - PKCS#8 - for other keys.
*/
type KeyAsn1Serializer struct {
    IKeySerializer
    cCtx *C.vscf_key_asn1_serializer_t /*ct10*/
}

func (obj *KeyAsn1Serializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_key_asn1_serializer_release_asn1_writer(obj.cCtx)
    C.vscf_key_asn1_serializer_use_asn1_writer(obj.cCtx, (*C.vscf_impl_t)(asn1Writer.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *KeyAsn1Serializer) SetupDefaults () {
    C.vscf_key_asn1_serializer_setup_defaults(obj.cCtx)

    return
}

/*
* Serialize Public Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (obj *KeyAsn1Serializer) SerializePublicKeyInplace (publicKey *RawPublicKey) (uint32, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_asn1_serializer_serialize_public_key_inplace(obj.cCtx, (*C.vscf_raw_public_key_t)(publicKey.ctx()), &error)

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
func (obj *KeyAsn1Serializer) SerializePrivateKeyInplace (privateKey *RawPrivateKey) (uint32, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_asn1_serializer_serialize_private_key_inplace(obj.cCtx, (*C.vscf_raw_private_key_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return 0, err
    }

    return uint32(proxyResult) /* r9 */, nil
}

/* Handle underlying C context. */
func (obj *KeyAsn1Serializer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewKeyAsn1Serializer () *KeyAsn1Serializer {
    ctx := C.vscf_key_asn1_serializer_new()
    return &KeyAsn1Serializer {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyAsn1SerializerWithCtx (ctx *C.vscf_key_asn1_serializer_t /*ct10*/) *KeyAsn1Serializer {
    return &KeyAsn1Serializer {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyAsn1SerializerCopy (ctx *C.vscf_key_asn1_serializer_t /*ct10*/) *KeyAsn1Serializer {
    return &KeyAsn1Serializer {
        cCtx: C.vscf_key_asn1_serializer_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (obj *KeyAsn1Serializer) clear () {
    C.vscf_key_asn1_serializer_delete(obj.cCtx)
}

/*
* Calculate buffer size enough to hold serialized public key.
*
* Precondition: public key must be exportable.
*/
func (obj *KeyAsn1Serializer) SerializedPublicKeyLen (publicKey *RawPublicKey) uint32 {
    proxyResult := /*pr4*/C.vscf_key_asn1_serializer_serialized_public_key_len(obj.cCtx, (*C.vscf_raw_public_key_t)(publicKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize given public key to an interchangeable format.
*
* Precondition: public key must be exportable.
*/
func (obj *KeyAsn1Serializer) SerializePublicKey (publicKey *RawPublicKey) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.SerializedPublicKeyLen(publicKey) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.clear()


    proxyResult := /*pr4*/C.vscf_key_asn1_serializer_serialize_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(publicKey.ctx()), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate buffer size enough to hold serialized private key.
*
* Precondition: private key must be exportable.
*/
func (obj *KeyAsn1Serializer) SerializedPrivateKeyLen (privateKey *RawPrivateKey) uint32 {
    proxyResult := /*pr4*/C.vscf_key_asn1_serializer_serialized_private_key_len(obj.cCtx, (*C.vscf_raw_private_key_t)(privateKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize given private key to an interchangeable format.
*
* Precondition: private key must be exportable.
*/
func (obj *KeyAsn1Serializer) SerializePrivateKey (privateKey *RawPrivateKey) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.SerializedPrivateKeyLen(privateKey) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.clear()


    proxyResult := /*pr4*/C.vscf_key_asn1_serializer_serialize_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(privateKey.ctx()), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}
