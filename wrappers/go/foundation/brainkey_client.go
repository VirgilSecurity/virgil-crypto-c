package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

type BrainkeyClient struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this BrainkeyClient) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewBrainkeyClient () *BrainkeyClient {
    ctx := C.vscf_brainkey_client_new()
    return &BrainkeyClient {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewBrainkeyClientWithCtx (ctx *C.vscf_impl_t) *BrainkeyClient {
    return &BrainkeyClient {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewBrainkeyClientCopy (ctx *C.vscf_impl_t) *BrainkeyClient {
    return &BrainkeyClient {
        ctx: C.vscf_brainkey_client_shallow_copy(ctx),
    }
}

func (this BrainkeyClient) getPointLen () int32 {
    return 65
}

func (this BrainkeyClient) getMpiLen () int32 {
    return 32
}

func (this BrainkeyClient) getSeedLen () int32 {
    return 32
}

func (this BrainkeyClient) getMaxPasswordLen () int32 {
    return 128
}

func (this BrainkeyClient) getMaxKeyNameLen () int32 {
    return 128
}

/*
* Random used for key generation, proofs, etc.
*/
func (this BrainkeyClient) SetRandom (random IRandom) {
    C.vscf_brainkey_client_release_random(this.ctx)
    C.vscf_brainkey_client_use_random(this.ctx, random.Ctx())
}

/*
* Random used for crypto operations to make them const-time
*/
func (this BrainkeyClient) SetOperationRandom (operationRandom IRandom) {
    C.vscf_brainkey_client_release_operation_random(this.ctx)
    C.vscf_brainkey_client_use_operation_random(this.ctx, operationRandom.Ctx())
}

func (this BrainkeyClient) SetupDefaults () {
    proxyResult := C.vscf_brainkey_client_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

func (this BrainkeyClient) Blind (password []byte) ([]byte, []byte) {
    deblindFactorCount := BrainkeyClient.getMpiLen() /* lg3 */
    deblindFactorBuf := NewBuffer(deblindFactorCount)
    defer deblindFactorBuf.Clear()

    blindedPointCount := BrainkeyClient.getPointLen() /* lg3 */
    blindedPointBuf := NewBuffer(blindedPointCount)
    defer blindedPointBuf.Clear()


    proxyResult := C.vscf_brainkey_client_blind(this.ctx, WrapData(password), deblindFactorBuf, blindedPointBuf)

    FoundationErrorHandleStatus(proxyResult)

    return deblindFactorBuf.GetData() /* r7 */, blindedPointBuf.GetData() /* r7 */
}

func (this BrainkeyClient) Deblind (password []byte, hardenedPoint []byte, deblindFactor []byte, keyName []byte) []byte {
    seedCount := BrainkeyClient.getPointLen() /* lg3 */
    seedBuf := NewBuffer(seedCount)
    defer seedBuf.Clear()


    proxyResult := C.vscf_brainkey_client_deblind(this.ctx, WrapData(password), WrapData(hardenedPoint), WrapData(deblindFactor), WrapData(keyName), seedBuf)

    FoundationErrorHandleStatus(proxyResult)

    return seedBuf.GetData() /* r7 */
}
