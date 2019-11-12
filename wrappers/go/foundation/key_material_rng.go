package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


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
func (obj *KeyMaterialRng) ResetKeyMaterial (keyMaterial []byte) {
    keyMaterialData := helperWrapData (keyMaterial)

    C.vscf_key_material_rng_reset_key_material(obj.cCtx, keyMaterialData)

    return
}

/* Handle underlying C context. */
func (obj *KeyMaterialRng) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
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

/*
* Release underlying C context.
*/
func (obj *KeyMaterialRng) Delete () {
    C.vscf_key_material_rng_delete(obj.cCtx)
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (obj *KeyMaterialRng) Random (dataLen uint32) ([]byte, error) {
    dataBuf, dataBufErr := bufferNewBuffer(int(dataLen))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.Delete()


    proxyResult := /*pr4*/C.vscf_key_material_rng_random(obj.cCtx, (C.size_t)(dataLen)/*pa10*/, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataBuf.getData() /* r7 */, nil
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (obj *KeyMaterialRng) Reseed () error {
    proxyResult := /*pr4*/C.vscf_key_material_rng_reseed(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}
