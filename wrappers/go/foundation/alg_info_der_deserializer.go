package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Provide DER deserializer of algorithm information.
*/
type AlgInfoDerDeserializer struct {
    cCtx *C.vscf_alg_info_der_deserializer_t /*ct10*/
}

func (obj *AlgInfoDerDeserializer) SetAsn1Reader(asn1Reader Asn1Reader) {
    C.vscf_alg_info_der_deserializer_release_asn1_reader(obj.cCtx)
    C.vscf_alg_info_der_deserializer_use_asn1_reader(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(asn1Reader.Ctx())))

    runtime.KeepAlive(asn1Reader)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *AlgInfoDerDeserializer) SetupDefaults() {
    C.vscf_alg_info_der_deserializer_setup_defaults(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Deserialize by using internal ASN.1 reader.
* Note, that caller code is responsible to reset ASN.1 reader with
* an input buffer.
*/
func (obj *AlgInfoDerDeserializer) DeserializeInplace() (AlgInfo, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_alg_info_der_deserializer_deserialize_inplace(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *AlgInfoDerDeserializer) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewAlgInfoDerDeserializer() *AlgInfoDerDeserializer {
    ctx := C.vscf_alg_info_der_deserializer_new()
    obj := &AlgInfoDerDeserializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*AlgInfoDerDeserializer).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAlgInfoDerDeserializerWithCtx(ctx *C.vscf_alg_info_der_deserializer_t /*ct10*/) *AlgInfoDerDeserializer {
    obj := &AlgInfoDerDeserializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*AlgInfoDerDeserializer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAlgInfoDerDeserializerCopy(ctx *C.vscf_alg_info_der_deserializer_t /*ct10*/) *AlgInfoDerDeserializer {
    obj := &AlgInfoDerDeserializer {
        cCtx: C.vscf_alg_info_der_deserializer_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*AlgInfoDerDeserializer).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *AlgInfoDerDeserializer) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *AlgInfoDerDeserializer) delete() {
    C.vscf_alg_info_der_deserializer_delete(obj.cCtx)
}

/*
* Deserialize algorithm from the data.
*/
func (obj *AlgInfoDerDeserializer) Deserialize(data []byte) (AlgInfo, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_alg_info_der_deserializer_deserialize(obj.cCtx, dataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}
