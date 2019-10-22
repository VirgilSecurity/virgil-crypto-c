package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Provide DER serializer of algorithm information.
*/
type AlgInfoDerSerializer struct {
    IAlgInfoSerializer
    ctx *C.vscf_impl_t
}

func (this AlgInfoDerSerializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_alg_info_der_serializer_release_asn1_writer(this.ctx)
    C.vscf_alg_info_der_serializer_use_asn1_writer(this.ctx, asn1Writer.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this AlgInfoDerSerializer) SetupDefaults () {
    C.vscf_alg_info_der_serializer_setup_defaults(this.ctx)
}

/*
* Serialize by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (this AlgInfoDerSerializer) SerializeInplace (algInfo IAlgInfo) int32 {
    proxyResult := C.vscf_alg_info_der_serializer_serialize_inplace(this.ctx, algInfo.Ctx())

    return proxyResult //r9
}

/* Handle underlying C context. */
func (this AlgInfoDerSerializer) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewAlgInfoDerSerializer () *AlgInfoDerSerializer {
    ctx := C.vscf_alg_info_der_serializer_new()
    return &AlgInfoDerSerializer {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAlgInfoDerSerializerWithCtx (ctx *C.vscf_impl_t) *AlgInfoDerSerializer {
    return &AlgInfoDerSerializer {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAlgInfoDerSerializerCopy (ctx *C.vscf_impl_t) *AlgInfoDerSerializer {
    return &AlgInfoDerSerializer {
        ctx: C.vscf_alg_info_der_serializer_shallow_copy(ctx),
    }
}

/*
* Return buffer size enough to hold serialized algorithm.
*/
func (this AlgInfoDerSerializer) SerializedLen (algInfo IAlgInfo) int32 {
    proxyResult := C.vscf_alg_info_der_serializer_serialized_len(this.ctx, algInfo.Ctx())

    return proxyResult //r9
}

/*
* Serialize algorithm info to buffer class.
*/
func (this AlgInfoDerSerializer) Serialize (algInfo IAlgInfo) []byte {
    outCount := this.SerializedLen(algInfo) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    C.vscf_alg_info_der_serializer_serialize(this.ctx, algInfo.Ctx(), outBuf)

    return outBuf.GetData() /* r7 */
}
