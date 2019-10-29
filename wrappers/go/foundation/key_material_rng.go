package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Random number generator that generate deterministic sequence based
* on a given seed.
* This RNG can be used to transform key material rial to the private key.
*/
type KeyMaterialRng struct {
    IRandom
    cCtx *C.vscf_key_material_rng_t /*ct10*/
}

/*
* Minimum length in bytes for the key material.
*/
func KeyMaterialRngGetKeyMaterialLenMin () uint32 {
    return 32
}

/*
* Maximum length in bytes for the key material.
*/
func KeyMaterialRngGetKeyMaterialLenMax () uint32 {
    return 512
}

/*
* Set a new key material.
*/
func (this KeyMaterialRng) ResetKeyMaterial (keyMaterial []byte) {
    keyMaterialData := C.vsc_data((*C.uint8_t)(&keyMaterial[0]), C.size_t(len(keyMaterial)))

    C.vscf_key_material_rng_reset_key_material(this.cCtx, keyMaterialData)

    return
}

/* Handle underlying C context. */
func (this KeyMaterialRng) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewKeyMaterialRng () *KeyMaterialRng {
    ctx := C.vscf_key_material_rng_new()
    return &KeyMaterialRng {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyMaterialRngWithCtx (ctx *C.vscf_key_material_rng_t /*ct10*/) *KeyMaterialRng {
    return &KeyMaterialRng {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyMaterialRngCopy (ctx *C.vscf_key_material_rng_t /*ct10*/) *KeyMaterialRng {
    return &KeyMaterialRng {
        cCtx: C.vscf_key_material_rng_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this KeyMaterialRng) close () {
    C.vscf_key_material_rng_delete(this.cCtx)
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (this KeyMaterialRng) Random (dataLen uint32) ([]byte, error) {
    dataCount := C.ulong(dataLen)
    dataMemory := make([]byte, int(C.vsc_buffer_ctx_size() + dataCount))
    dataBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&dataMemory[0]))
    dataData := dataMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(dataBuf)
    C.vsc_buffer_use(dataBuf, (*C.byte)(unsafe.Pointer(&dataData[0])), dataCount)
    defer C.vsc_buffer_delete(dataBuf)


    proxyResult := /*pr4*/C.vscf_key_material_rng_random(this.cCtx, (C.size_t)(dataLen)/*pa10*/, dataBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataData[0:C.vsc_buffer_len(dataBuf)] /* r7 */, nil
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (this KeyMaterialRng) Reseed () error {
    proxyResult := /*pr4*/C.vscf_key_material_rng_reseed(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}
