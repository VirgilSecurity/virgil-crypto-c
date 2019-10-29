package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

type BrainkeyClient struct {
    cCtx *C.vscf_brainkey_client_t /*ct2*/
}

/* Handle underlying C context. */
func (this BrainkeyClient) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
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

/// Release underlying C context.
func (this BrainkeyClient) close () {
    C.vscf_brainkey_client_delete(this.cCtx)
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
func (this BrainkeyClient) SetRandom (random IRandom) {
    C.vscf_brainkey_client_release_random(this.cCtx)
    C.vscf_brainkey_client_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

/*
* Random used for crypto operations to make them const-time
*/
func (this BrainkeyClient) SetOperationRandom (operationRandom IRandom) {
    C.vscf_brainkey_client_release_operation_random(this.cCtx)
    C.vscf_brainkey_client_use_operation_random(this.cCtx, (*C.vscf_impl_t)(operationRandom.ctx()))
}

func (this BrainkeyClient) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_brainkey_client_setup_defaults(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

func (this BrainkeyClient) Blind (password []byte) ([]byte, []byte, error) {
    deblindFactorCount := C.ulong(BrainkeyClientGetMpiLen() /* lg4 */)
    deblindFactorMemory := make([]byte, int(C.vsc_buffer_ctx_size() + deblindFactorCount))
    deblindFactorBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&deblindFactorMemory[0]))
    deblindFactorData := deblindFactorMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(deblindFactorBuf)
    C.vsc_buffer_use(deblindFactorBuf, (*C.byte)(unsafe.Pointer(&deblindFactorData[0])), deblindFactorCount)
    defer C.vsc_buffer_delete(deblindFactorBuf)

    blindedPointCount := C.ulong(BrainkeyClientGetPointLen() /* lg4 */)
    blindedPointMemory := make([]byte, int(C.vsc_buffer_ctx_size() + blindedPointCount))
    blindedPointBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&blindedPointMemory[0]))
    blindedPointData := blindedPointMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(blindedPointBuf)
    C.vsc_buffer_use(blindedPointBuf, (*C.byte)(unsafe.Pointer(&blindedPointData[0])), blindedPointCount)
    defer C.vsc_buffer_delete(blindedPointBuf)
    passwordData := C.vsc_data((*C.uint8_t)(&password[0]), C.size_t(len(password)))

    proxyResult := /*pr4*/C.vscf_brainkey_client_blind(this.cCtx, passwordData, deblindFactorBuf, blindedPointBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    return deblindFactorData[0:C.vsc_buffer_len(deblindFactorBuf)] /* r7 */, blindedPointData[0:C.vsc_buffer_len(blindedPointBuf)] /* r7 */, nil
}

func (this BrainkeyClient) Deblind (password []byte, hardenedPoint []byte, deblindFactor []byte, keyName []byte) ([]byte, error) {
    seedCount := C.ulong(BrainkeyClientGetPointLen() /* lg4 */)
    seedMemory := make([]byte, int(C.vsc_buffer_ctx_size() + seedCount))
    seedBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&seedMemory[0]))
    seedData := seedMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(seedBuf)
    C.vsc_buffer_use(seedBuf, (*C.byte)(unsafe.Pointer(&seedData[0])), seedCount)
    defer C.vsc_buffer_delete(seedBuf)
    passwordData := C.vsc_data((*C.uint8_t)(&password[0]), C.size_t(len(password)))
    hardenedPointData := C.vsc_data((*C.uint8_t)(&hardenedPoint[0]), C.size_t(len(hardenedPoint)))
    deblindFactorData := C.vsc_data((*C.uint8_t)(&deblindFactor[0]), C.size_t(len(deblindFactor)))
    keyNameData := C.vsc_data((*C.uint8_t)(&keyName[0]), C.size_t(len(keyName)))

    proxyResult := /*pr4*/C.vscf_brainkey_client_deblind(this.cCtx, passwordData, hardenedPointData, deblindFactorData, keyNameData, seedBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return seedData[0:C.vsc_buffer_len(seedBuf)] /* r7 */, nil
}
