package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Implements SEC 1 key serialization to DER format.
* See also RFC 5480 and RFC 5915.
*/
type Sec1Serializer struct {
    cCtx *C.vscf_sec1_serializer_t /*ct10*/
}

func (obj *Sec1Serializer) SetAsn1Writer(asn1Writer Asn1Writer) {
    C.vscf_sec1_serializer_release_asn1_writer(obj.cCtx)
    C.vscf_sec1_serializer_use_asn1_writer(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(asn1Writer.Ctx())))

    runtime.KeepAlive(asn1Writer)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Sec1Serializer) SetupDefaults() {
    C.vscf_sec1_serializer_setup_defaults(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Serialize Public Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (obj *Sec1Serializer) SerializePublicKeyInplace(publicKey *RawPublicKey) (int, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_sec1_serializer_serialize_public_key_inplace(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(publicKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return 0, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return int(proxyResult) /* r9 */, nil
}

/*
* Serialize Private Key by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (obj *Sec1Serializer) SerializePrivateKeyInplace(privateKey *RawPrivateKey) (int, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_sec1_serializer_serialize_private_key_inplace(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(privateKey.Ctx())), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return 0, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return int(proxyResult) /* r9 */, nil
}

/* Handle underlying C context. */
func (obj *Sec1Serializer) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewSec1Serializer() *Sec1Serializer {
    ctx := C.vscf_sec1_serializer_new()
    obj := &Sec1Serializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Sec1Serializer).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSec1SerializerWithCtx(ctx *C.vscf_sec1_serializer_t /*ct10*/) *Sec1Serializer {
    obj := &Sec1Serializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Sec1Serializer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSec1SerializerCopy(ctx *C.vscf_sec1_serializer_t /*ct10*/) *Sec1Serializer {
    obj := &Sec1Serializer {
        cCtx: C.vscf_sec1_serializer_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Sec1Serializer).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Sec1Serializer) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Sec1Serializer) delete() {
    C.vscf_sec1_serializer_delete(obj.cCtx)
}

/*
* Calculate buffer size enough to hold serialized public key.
*
* Precondition: public key must be exportable.
*/
func (obj *Sec1Serializer) SerializedPublicKeyLen(publicKey *RawPublicKey) int {
    proxyResult := /*pr4*/C.vscf_sec1_serializer_serialized_public_key_len(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return int(proxyResult) /* r9 */
}

/*
* Serialize given public key to an interchangeable format.
*
* Precondition: public key must be exportable.
*/
func (obj *Sec1Serializer) SerializePublicKey(publicKey *RawPublicKey) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.SerializedPublicKeyLen(publicKey) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_sec1_serializer_serialize_public_key(obj.cCtx, (*C.vscf_raw_public_key_t)(unsafe.Pointer(publicKey.Ctx())), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate buffer size enough to hold serialized private key.
*
* Precondition: private key must be exportable.
*/
func (obj *Sec1Serializer) SerializedPrivateKeyLen(privateKey *RawPrivateKey) int {
    proxyResult := /*pr4*/C.vscf_sec1_serializer_serialized_private_key_len(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return int(proxyResult) /* r9 */
}

/*
* Serialize given private key to an interchangeable format.
*
* Precondition: private key must be exportable.
*/
func (obj *Sec1Serializer) SerializePrivateKey(privateKey *RawPrivateKey) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.SerializedPrivateKeyLen(privateKey) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_sec1_serializer_serialize_private_key(obj.cCtx, (*C.vscf_raw_private_key_t)(unsafe.Pointer(privateKey.Ctx())), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return outBuf.getData() /* r7 */, nil
}
