package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Implements PKCS#8 and SEC1 key deserialization from DER / PEM format.
*/
type KeyAsn1Deserializer struct {
    cCtx *C.vscf_key_asn1_deserializer_t /*ct10*/
}

func (obj *KeyAsn1Deserializer) SetAsn1Reader(asn1Reader Asn1Reader) {
    C.vscf_key_asn1_deserializer_release_asn1_reader(obj.cCtx)
    C.vscf_key_asn1_deserializer_use_asn1_reader(obj.cCtx, (*C.vscf_impl_t)(asn1Reader.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *KeyAsn1Deserializer) SetupDefaults() {
    C.vscf_key_asn1_deserializer_setup_defaults(obj.cCtx)

    return
}

/*
* Deserialize Public Key by using internal ASN.1 reader.
* Note, that caller code is responsible to reset ASN.1 reader with
* an input buffer.
*/
func (obj *KeyAsn1Deserializer) DeserializePublicKeyInplace() (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_asn1_deserializer_deserialize_public_key_inplace(obj.cCtx, &error)

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
func (obj *KeyAsn1Deserializer) DeserializePrivateKeyInplace() (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_asn1_deserializer_deserialize_private_key_inplace(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}

/* Handle underlying C context. */
func (obj *KeyAsn1Deserializer) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewKeyAsn1Deserializer() *KeyAsn1Deserializer {
    ctx := C.vscf_key_asn1_deserializer_new()
    obj := &KeyAsn1Deserializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, func (o *KeyAsn1Deserializer) {o.Delete()})
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyAsn1DeserializerWithCtx(ctx *C.vscf_key_asn1_deserializer_t /*ct10*/) *KeyAsn1Deserializer {
    obj := &KeyAsn1Deserializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, func (o *KeyAsn1Deserializer) {o.Delete()})
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyAsn1DeserializerCopy(ctx *C.vscf_key_asn1_deserializer_t /*ct10*/) *KeyAsn1Deserializer {
    obj := &KeyAsn1Deserializer {
        cCtx: C.vscf_key_asn1_deserializer_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, func (o *KeyAsn1Deserializer) {o.Delete()})
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyAsn1Deserializer) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KeyAsn1Deserializer) delete() {
    C.vscf_key_asn1_deserializer_delete(obj.cCtx)
}

/*
* Deserialize given public key as an interchangeable format to the object.
*/
func (obj *KeyAsn1Deserializer) DeserializePublicKey(publicKeyData []byte) (*RawPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    publicKeyDataData := helperWrapData (publicKeyData)

    proxyResult := /*pr4*/C.vscf_key_asn1_deserializer_deserialize_public_key(obj.cCtx, publicKeyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPublicKeyWithCtx(proxyResult) /* r6 */, nil
}

/*
* Deserialize given private key as an interchangeable format to the object.
*/
func (obj *KeyAsn1Deserializer) DeserializePrivateKey(privateKeyData []byte) (*RawPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    privateKeyDataData := helperWrapData (privateKeyData)

    proxyResult := /*pr4*/C.vscf_key_asn1_deserializer_deserialize_private_key(obj.cCtx, privateKeyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRawPrivateKeyWithCtx(proxyResult) /* r6 */, nil
}
