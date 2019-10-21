package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"

/*
* Handle meta information about footer.
*/
type FooterInfo struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this FooterInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewFooterInfo () *FooterInfo {
    ctx := C.vscf_footer_info_new()
    return &FooterInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewFooterInfoWithCtx (ctx *C.vscf_impl_t) *FooterInfo {
    return &FooterInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewFooterInfoCopy (ctx *C.vscf_impl_t) *FooterInfo {
    return &FooterInfo {
        ctx: C.vscf_footer_info_shallow_copy(ctx),
    }
}

/*
* Retrun true if signed data info present.
*/
func (this FooterInfo) HasSignedDataInfo () bool {
    proxyResult := C.vscf_footer_info_has_signed_data_info(this.ctx)

    return proxyResult //r9
}

/*
* Return signed data info.
*/
func (this FooterInfo) SignedDataInfo () SignedDataInfo {
    proxyResult := C.vscf_footer_info_signed_data_info(this.ctx)

    return SignedDataInfo.init(use: proxyResult!) /* r5 */
}

/*
* Set data size.
*/
func (this FooterInfo) SetDataSize (dataSize int32) {
    C.vscf_footer_info_set_data_size(this.ctx, dataSize)
}

/*
* Return data size.
*/
func (this FooterInfo) DataSize () int32 {
    proxyResult := C.vscf_footer_info_data_size(this.ctx)

    return proxyResult //r9
}
