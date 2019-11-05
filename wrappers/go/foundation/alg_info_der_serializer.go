package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Provide DER serializer of algorithm information.
*/
type AlgInfoDerSerializer struct {
    IAlgInfoSerializer
    cCtx *C.vscf_alg_info_der_serializer_t /*ct10*/
}

func (this AlgInfoDerSerializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_alg_info_der_serializer_release_asn1_writer(this.cCtx)
    C.vscf_alg_info_der_serializer_use_asn1_writer(this.cCtx, (*C.vscf_impl_t)(asn1Writer.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this AlgInfoDerSerializer) SetupDefaults () {
    C.vscf_alg_info_der_serializer_setup_defaults(this.cCtx)

    return
}

/*
* Serialize by using internal ASN.1 writer.
* Note, that caller code is responsible to reset ASN.1 writer with
* an output buffer.
*/
func (this AlgInfoDerSerializer) SerializeInplace (algInfo IAlgInfo) uint32 {
    proxyResult := /*pr4*/C.vscf_alg_info_der_serializer_serialize_inplace(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    return uint32(proxyResult) /* r9 */
}

/* Handle underlying C context. */
func (this AlgInfoDerSerializer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewAlgInfoDerSerializer () *AlgInfoDerSerializer {
    ctx := C.vscf_alg_info_der_serializer_new()
    return &AlgInfoDerSerializer {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAlgInfoDerSerializerWithCtx (ctx *C.vscf_alg_info_der_serializer_t /*ct10*/) *AlgInfoDerSerializer {
    return &AlgInfoDerSerializer {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAlgInfoDerSerializerCopy (ctx *C.vscf_alg_info_der_serializer_t /*ct10*/) *AlgInfoDerSerializer {
    return &AlgInfoDerSerializer {
        cCtx: C.vscf_alg_info_der_serializer_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this AlgInfoDerSerializer) clear () {
    C.vscf_alg_info_der_serializer_delete(this.cCtx)
}

/*
* Return buffer size enough to hold serialized algorithm.
*/
func (this AlgInfoDerSerializer) SerializedLen (algInfo IAlgInfo) uint32 {
    proxyResult := /*pr4*/C.vscf_alg_info_der_serializer_serialized_len(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize algorithm info to buffer class.
*/
func (this AlgInfoDerSerializer) Serialize (algInfo IAlgInfo) []byte {
    outBuf, outBufErr := bufferNewBuffer(int(this.SerializedLen(algInfo.(IAlgInfo)) /* lg2 */))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.clear()


    C.vscf_alg_info_der_serializer_serialize(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()), outBuf.ctx)

    return outBuf.getData() /* r7 */
}
