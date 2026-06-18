package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Threshold secret sharing based on Shamir's scheme over GF(256).
*
* Splits an arbitrary-length secret into 'share count' shares so that any
* 'threshold' of them reconstruct the secret, while fewer reveal nothing.
*
* Construction (split-key-encrypt-data): a random 32-byte data key is
* generated, the secret is encrypted with it using AES-256-GCM, and only the
* data key is Shamir-split. Each share is self-contained (it embeds the
* encrypted secret). Recovery combines the shares to rebuild the data key,
* verifies a commitment to it, and authenticates the decryption with the GCM
* tag - so wrong, tampered, insufficient, or cross-split shares fail cleanly.
*/
type Shamir struct {
    cCtx *C.vscf_shamir_t
}

/* Handle underlying C context. */
func (obj *Shamir) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewShamir() *Shamir {
    ctx := C.vscf_shamir_new()
    obj := &Shamir {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Shamir).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newShamirWithCtx(ctx *C.vscf_shamir_t) *Shamir {
    obj := &Shamir {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Shamir).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newShamirCopy(ctx *C.vscf_shamir_t) *Shamir {
    obj := &Shamir {
        cCtx: C.vscf_shamir_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Shamir).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Shamir) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Shamir) delete() {
    C.vscf_shamir_delete(obj.cCtx)
}

func (obj *Shamir) SetRandom(random Random) {
    C.vscf_shamir_release_random(obj.cCtx)
    C.vscf_shamir_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies:
* a CTR DRBG random number generator.
*/
func (obj *Shamir) SetupDefaults() error {
    proxyResult := C.vscf_shamir_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Calculate the length in bytes of a single share produced for a secret
* of the given length.
*/
func (obj *Shamir) ShareLen(secretLen uint) uint {
    proxyResult := C.vscf_shamir_share_len((C.size_t)(secretLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Calculate the length in bytes of the buffer needed to hold all shares
* produced by 'split' for a secret of the given length and the given
* number of shares.
*/
func (obj *Shamir) SharesLen(secretLen uint, shareCount uint) uint {
    proxyResult := C.vscf_shamir_shares_len((C.size_t)(secretLen), (C.size_t)(shareCount))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Calculate an upper bound on the length in bytes of the recovered secret
* for the given total shares length and number of provided shares.
* The exact length is set on the output buffer by 'combine'.
*/
func (obj *Shamir) RecoveredSecretLen(sharesLen uint, shareCount uint) uint {
    proxyResult := C.vscf_shamir_recovered_secret_len((C.size_t)(sharesLen), (C.size_t)(shareCount))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Split the given secret into 'share count' shares with reconstruction
* 'threshold'. Requires a configured random number generator (see
* 'setup defaults' / 'use random').
*
* Constraints: 1 <= threshold <= share count <= 255.
*
* The produced shares are written consecutively to 'out', each of length
* 'share len(secret.len)'.
*/
func (obj *Shamir) Split(secret []byte, threshold uint, shareCount uint) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.SharesLen(uint(len(secret)), shareCount)))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    secretData := helperWrapData (secret)

    proxyResult := C.vscf_shamir_split(obj.cCtx, secretData, (C.size_t)(threshold), (C.size_t)(shareCount), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Reconstruct the secret from 'share count' shares concatenated in
* 'shares'. 'share count' must be at least the threshold used at split
* time.
*
* Returns 'success' and writes the secret to 'secret' on success.
* Returns 'error shamir recovery failed' if the shares are wrong,
* tampered, insufficient, or do not belong to the same split.
*/
func (obj *Shamir) Combine(shares []byte, shareCount uint) ([]byte, error) {
    secretBuf, secretBufErr := newBuffer(int(obj.RecoveredSecretLen(uint(len(shares)), shareCount)))
    if secretBufErr != nil {
        return nil, secretBufErr
    }
    defer secretBuf.delete()
    sharesData := helperWrapData (shares)

    proxyResult := C.vscf_shamir_combine(obj.cCtx, sharesData, (C.size_t)(shareCount), secretBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return secretBuf.getData(), nil
}
