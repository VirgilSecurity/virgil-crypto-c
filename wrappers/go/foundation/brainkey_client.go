package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


type BrainkeyClient struct {
    cCtx *C.vscf_brainkey_client_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *BrainkeyClient) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewBrainkeyClient () *BrainkeyClient {
    ctx := C.vscf_brainkey_client_new()
    return &BrainkeyClient {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyClientWithCtx (ctx *C.vscf_brainkey_client_t /*ct2*/) *BrainkeyClient {
    return &BrainkeyClient {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyClientCopy (ctx *C.vscf_brainkey_client_t /*ct2*/) *BrainkeyClient {
    return &BrainkeyClient {
        cCtx: C.vscf_brainkey_client_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyClient) Delete () {
    C.vscf_brainkey_client_delete(obj.cCtx)
}

func BrainkeyClientGetPointLen () uint32 {
    return 65
}

func BrainkeyClientGetMpiLen () uint32 {
    return 32
}

func BrainkeyClientGetSeedLen () uint32 {
    return 32
}

func BrainkeyClientGetMaxPasswordLen () uint32 {
    return 128
}

func BrainkeyClientGetMaxKeyNameLen () uint32 {
    return 128
}

/*
* Random used for key generation, proofs, etc.
*/
func (obj *BrainkeyClient) SetRandom (random IRandom) {
    C.vscf_brainkey_client_release_random(obj.cCtx)
    C.vscf_brainkey_client_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

/*
* Random used for crypto operations to make them const-time
*/
func (obj *BrainkeyClient) SetOperationRandom (operationRandom IRandom) {
    C.vscf_brainkey_client_release_operation_random(obj.cCtx)
    C.vscf_brainkey_client_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(operationRandom.ctx()))
}

func (obj *BrainkeyClient) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_brainkey_client_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

func (obj *BrainkeyClient) Blind (password []byte) ([]byte, []byte, error) {
    deblindFactorBuf, deblindFactorBufErr := bufferNewBuffer(int(BrainkeyClientGetMpiLen() /* lg4 */))
    if deblindFactorBufErr != nil {
        return nil, nil, deblindFactorBufErr
    }
    defer deblindFactorBuf.Delete()

    blindedPointBuf, blindedPointBufErr := bufferNewBuffer(int(BrainkeyClientGetPointLen() /* lg4 */))
    if blindedPointBufErr != nil {
        return nil, nil, blindedPointBufErr
    }
    defer blindedPointBuf.Delete()
    passwordData := helperWrapData (password)

    proxyResult := /*pr4*/C.vscf_brainkey_client_blind(obj.cCtx, passwordData, deblindFactorBuf.ctx, blindedPointBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    return deblindFactorBuf.getData() /* r7 */, blindedPointBuf.getData() /* r7 */, nil
}

func (obj *BrainkeyClient) Deblind (password []byte, hardenedPoint []byte, deblindFactor []byte, keyName []byte) ([]byte, error) {
    seedBuf, seedBufErr := bufferNewBuffer(int(BrainkeyClientGetPointLen() /* lg4 */))
    if seedBufErr != nil {
        return nil, seedBufErr
    }
    defer seedBuf.Delete()
    passwordData := helperWrapData (password)
    hardenedPointData := helperWrapData (hardenedPoint)
    deblindFactorData := helperWrapData (deblindFactor)
    keyNameData := helperWrapData (keyName)

    proxyResult := /*pr4*/C.vscf_brainkey_client_deblind(obj.cCtx, passwordData, hardenedPointData, deblindFactorData, keyNameData, seedBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return seedBuf.getData() /* r7 */, nil
}
