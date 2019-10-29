package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle meta information about footer.
*/
type FooterInfo struct {
    cCtx *C.vscf_footer_info_t /*ct2*/
}

/* Handle underlying C context. */
func (this FooterInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewFooterInfo () *FooterInfo {
    ctx := C.vscf_footer_info_new()
    return &FooterInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newFooterInfoWithCtx (ctx *C.vscf_footer_info_t /*ct2*/) *FooterInfo {
    return &FooterInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newFooterInfoCopy (ctx *C.vscf_footer_info_t /*ct2*/) *FooterInfo {
    return &FooterInfo {
        cCtx: C.vscf_footer_info_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this FooterInfo) close () {
    C.vscf_footer_info_delete(this.cCtx)
}

/*
* Retrun true if signed data info present.
*/
func (this FooterInfo) HasSignedDataInfo () bool {
    proxyResult := /*pr4*/C.vscf_footer_info_has_signed_data_info(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return signed data info.
*/
func (this FooterInfo) SignedDataInfo () *SignedDataInfo {
    proxyResult := /*pr4*/C.vscf_footer_info_signed_data_info(this.cCtx)

    return newSignedDataInfoWithCtx(proxyResult) /* r5 */
}

/*
* Set data size.
*/
func (this FooterInfo) SetDataSize (dataSize uint32) {
    C.vscf_footer_info_set_data_size(this.cCtx, (C.size_t)(dataSize)/*pa10*/)

    return
}

/*
* Return data size.
*/
func (this FooterInfo) DataSize () uint32 {
    proxyResult := /*pr4*/C.vscf_footer_info_data_size(this.cCtx)

    return uint32(proxyResult) /* r9 */
}
