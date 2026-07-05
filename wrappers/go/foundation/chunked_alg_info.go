package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handle chunk cipher algorithm information, i.e. AES-256-GCM in
* the chunked framing mode. Carries the framing parameters directly:
* a version, the chunk size, and the initial nonce.
*/
type ChunkedAlgInfo struct {
    cCtx *C.vscf_chunked_alg_info_t
}

/*
* Create chunk cipher algorithm info with identificator, version,
* chunk size and the initial nonce.
*/
func NewChunkedAlgInfoWithMembers(algId AlgId, version uint, chunkSize uint, nonce []byte) *ChunkedAlgInfo {
    nonceData := helperWrapData (nonce)

    proxyResult := C.vscf_chunked_alg_info_new_with_members(C.vscf_alg_id_t(algId), (C.size_t)(version), (C.size_t)(chunkSize), nonceData)

    obj := &ChunkedAlgInfo {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*ChunkedAlgInfo).Delete)
    return obj
}

/*
* Return chunk cipher alg info version.
*/
func (obj *ChunkedAlgInfo) Version() uint {
    proxyResult := C.vscf_chunked_alg_info_version(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return chunk size.
*/
func (obj *ChunkedAlgInfo) ChunkSize() uint {
    proxyResult := C.vscf_chunked_alg_info_chunk_size(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return the initial nonce.
*/
func (obj *ChunkedAlgInfo) Nonce() []byte {
    proxyResult := C.vscf_chunked_alg_info_nonce(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}

/* Handle underlying C context. */
func (obj *ChunkedAlgInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewChunkedAlgInfo() *ChunkedAlgInfo {
    ctx := C.vscf_chunked_alg_info_new()
    obj := &ChunkedAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChunkedAlgInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChunkedAlgInfoWithCtx(ctx *C.vscf_chunked_alg_info_t) *ChunkedAlgInfo {
    obj := &ChunkedAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChunkedAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChunkedAlgInfoCopy(ctx *C.vscf_chunked_alg_info_t) *ChunkedAlgInfo {
    obj := &ChunkedAlgInfo {
        cCtx: C.vscf_chunked_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*ChunkedAlgInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *ChunkedAlgInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *ChunkedAlgInfo) delete() {
    C.vscf_chunked_alg_info_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *ChunkedAlgInfo) AlgId() AlgId {
    proxyResult := C.vscf_chunked_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}
