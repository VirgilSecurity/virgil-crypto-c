package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Provide DER serializer of algorithm information.
*/
type AlgInfoDerSerializer struct {
    cCtx *C.vscf_alg_info_der_serializer_t /*ct10*/
}

func (obj *AlgInfoDerSerializer) SetAsn1Writer(asn1Writer Asn1Writer) {
    C.vscf_alg_info_der_serializer_release_asn1_writer(obj.cCtx)
    C.vscf_alg_info_der_serializer_use_asn1_writer(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(asn1Writer.Ctx())))

    runtime.KeepAlive(asn1Writer)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *AlgInfoDerSerializer) SetupDefaults() {
    C.vscf_alg_info_der_serializer_setup_defaults(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Serialize by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (obj *AlgInfoDerSerializer) SerializeInplace(algInfo AlgInfo) int {
    proxyResult := /*pr4*/C.vscf_alg_info_der_serializer_serialize_inplace(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return int(proxyResult) /* r9 */
}

/* Handle underlying C context. */
func (obj *AlgInfoDerSerializer) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewAlgInfoDerSerializer() *AlgInfoDerSerializer {
    ctx := C.vscf_alg_info_der_serializer_new()
    obj := &AlgInfoDerSerializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*AlgInfoDerSerializer).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAlgInfoDerSerializerWithCtx(ctx *C.vscf_alg_info_der_serializer_t /*ct10*/) *AlgInfoDerSerializer {
    obj := &AlgInfoDerSerializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*AlgInfoDerSerializer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAlgInfoDerSerializerCopy(ctx *C.vscf_alg_info_der_serializer_t /*ct10*/) *AlgInfoDerSerializer {
    obj := &AlgInfoDerSerializer {
        cCtx: C.vscf_alg_info_der_serializer_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*AlgInfoDerSerializer).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *AlgInfoDerSerializer) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *AlgInfoDerSerializer) delete() {
    C.vscf_alg_info_der_serializer_delete(obj.cCtx)
}

/*
* Return buffer size enough to hold serialized algorithm.
*/
func (obj *AlgInfoDerSerializer) SerializedLen(algInfo AlgInfo) int {
    proxyResult := /*pr4*/C.vscf_alg_info_der_serializer_serialized_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return int(proxyResult) /* r9 */
}

/*
* Serialize algorithm info to buffer class.
*/
func (obj *AlgInfoDerSerializer) Serialize(algInfo AlgInfo) []byte {
    outBuf, outBufErr := bufferNewBuffer(int(obj.SerializedLen(algInfo.(AlgInfo)) /* lg2 */))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.Delete()


    C.vscf_alg_info_der_serializer_serialize(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())), outBuf.ctx)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return outBuf.getData() /* r7 */
}
