package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Random number generator that generate deterministic sequence based
* on a given seed.
* This RNG can be used to transform key material rial to the private key.
*/
type KeyMaterialRng struct {
    IRandom
    ctx *C.vscf_impl_t
}

/*
* Minimum length in bytes for the key material.
*/
func (this KeyMaterialRng) getKeyMaterialLenMin () int32 {
    return 32
}

/*
* Maximum length in bytes for the key material.
*/
func (this KeyMaterialRng) getKeyMaterialLenMax () int32 {
    return 512
}

/*
* Set a new key material.
*/
func (this KeyMaterialRng) ResetKeyMaterial (keyMaterial []byte) {
    C.vscf_key_material_rng_reset_key_material(this.ctx, WrapData(keyMaterial))
}

/* Handle underlying C context. */
func (this KeyMaterialRng) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewKeyMaterialRng () *KeyMaterialRng {
    ctx := C.vscf_key_material_rng_new()
    return &KeyMaterialRng {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyMaterialRngWithCtx (ctx *C.vscf_impl_t) *KeyMaterialRng {
    return &KeyMaterialRng {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyMaterialRngCopy (ctx *C.vscf_impl_t) *KeyMaterialRng {
    return &KeyMaterialRng {
        ctx: C.vscf_key_material_rng_shallow_copy(ctx),
    }
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (this KeyMaterialRng) Random (dataLen int32) []byte {
    dataCount := dataLen
    dataBuf := NewBuffer(dataCount)
    defer dataBuf.Clear()


    proxyResult := C.vscf_key_material_rng_random(this.ctx, dataLen, dataBuf)

    FoundationErrorHandleStatus(proxyResult)

    return dataBuf.GetData() /* r7 */
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (this KeyMaterialRng) Reseed () {
    proxyResult := C.vscf_key_material_rng_reseed(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}
