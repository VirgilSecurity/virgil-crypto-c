package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

type BrainkeyServer struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this BrainkeyServer) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewBrainkeyServer () *BrainkeyServer {
    ctx := C.vscf_brainkey_server_new()
    return &BrainkeyServer {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewBrainkeyServerWithCtx (ctx *C.vscf_impl_t) *BrainkeyServer {
    return &BrainkeyServer {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewBrainkeyServerCopy (ctx *C.vscf_impl_t) *BrainkeyServer {
    return &BrainkeyServer {
        ctx: C.vscf_brainkey_server_shallow_copy(ctx),
    }
}

func (this BrainkeyServer) getPointLen () int32 {
    return 65
}

func (this BrainkeyServer) getMpiLen () int32 {
    return 32
}

/*
* Random used for key generation, proofs, etc.
*/
func (this BrainkeyServer) SetRandom (random IRandom) {
    C.vscf_brainkey_server_release_random(this.ctx)
    C.vscf_brainkey_server_use_random(this.ctx, random.Ctx())
}

/*
* Random used for crypto operations to make them const-time
*/
func (this BrainkeyServer) SetOperationRandom (operationRandom IRandom) {
    C.vscf_brainkey_server_release_operation_random(this.ctx)
    C.vscf_brainkey_server_use_operation_random(this.ctx, operationRandom.Ctx())
}

func (this BrainkeyServer) SetupDefaults () {
    proxyResult := C.vscf_brainkey_server_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

func (this BrainkeyServer) GenerateIdentitySecret () []byte {
    identitySecretCount := BrainkeyServer.getMpiLen() /* lg3 */
    identitySecretBuf := NewBuffer(identitySecretCount)
    defer identitySecretBuf.Clear()


    proxyResult := C.vscf_brainkey_server_generate_identity_secret(this.ctx, identitySecretBuf)

    FoundationErrorHandleStatus(proxyResult)

    return identitySecretBuf.GetData() /* r7 */
}

func (this BrainkeyServer) Harden (identitySecret []byte, blindedPoint []byte) []byte {
    hardenedPointCount := BrainkeyServer.getPointLen() /* lg3 */
    hardenedPointBuf := NewBuffer(hardenedPointCount)
    defer hardenedPointBuf.Clear()


    proxyResult := C.vscf_brainkey_server_harden(this.ctx, WrapData(identitySecret), WrapData(blindedPoint), hardenedPointBuf)

    FoundationErrorHandleStatus(proxyResult)

    return hardenedPointBuf.GetData() /* r7 */
}
