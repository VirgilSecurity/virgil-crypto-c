package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Provide DER deserializer of algorithm information.
*/
type AlgInfoDerDeserializer struct {
    IAlgInfoDeserializer
    ctx *C.vscf_impl_t
}

func (this AlgInfoDerDeserializer) SetAsn1Reader (asn1Reader IAsn1Reader) {
    C.vscf_alg_info_der_deserializer_release_asn1_reader(this.ctx)
    C.vscf_alg_info_der_deserializer_use_asn1_reader(this.ctx, asn1Reader.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this AlgInfoDerDeserializer) SetupDefaults () {
    C.vscf_alg_info_der_deserializer_setup_defaults(this.ctx)
}

/*
* Deserialize by using internal ASN.1 reader.
* Note, that caller code is responsible to reset ASN.1 reader with
* an input buffer.
*/
func (this AlgInfoDerDeserializer) DeserializeInplace () IAlgInfo {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_alg_info_der_deserializer_deserialize_inplace(this.ctx, &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this AlgInfoDerDeserializer) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewAlgInfoDerDeserializer () *AlgInfoDerDeserializer {
    ctx := C.vscf_alg_info_der_deserializer_new()
    return &AlgInfoDerDeserializer {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAlgInfoDerDeserializerWithCtx (ctx *C.vscf_impl_t) *AlgInfoDerDeserializer {
    return &AlgInfoDerDeserializer {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAlgInfoDerDeserializerCopy (ctx *C.vscf_impl_t) *AlgInfoDerDeserializer {
    return &AlgInfoDerDeserializer {
        ctx: C.vscf_alg_info_der_deserializer_shallow_copy(ctx),
    }
}

/*
* Deserialize algorithm from the data.
*/
func (this AlgInfoDerDeserializer) Deserialize (data []byte) IAlgInfo {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_alg_info_der_deserializer_deserialize(this.ctx, WrapData(data), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}
