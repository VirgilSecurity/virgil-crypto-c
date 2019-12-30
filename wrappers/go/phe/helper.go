package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import unsafe "unsafe"


type helper struct {
}

func helperBytesToBytePtr(data []byte) *C.uint8_t {
    return (*C.uint8_t)(&data[0])
}

func helperWrapData(data []byte) C.vsc_data_t {
    if len(data) == 0 {
        return C.vsc_data_empty()
    }
    return C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))
}

func helperExtractData(data C.vsc_data_t) []byte {
    newSize := data.len
    //FIXME Verify data is not corrupted
    //if newSize < len(data.bytes) {
    //    panic("Underlying C buffer corrupt the memory.")
    //}
    return C.GoBytes(unsafe.Pointer(data.bytes), C.int(newSize))
}

type buffer struct {
    memory []byte
    ctx *C.vsc_buffer_t
    data []byte
}

func newBuffer(cap int) (*buffer, error) {
    capacity := C.size_t(cap)
    if capacity == 0 {
        return nil, &PheError{-1,"Buffer with zero capacity is not allowed."}
    }

    ctxLen := C.vsc_buffer_ctx_size()
    memory := make([]byte, int(ctxLen + capacity))
    ctx := (*C.vsc_buffer_t)(unsafe.Pointer(&memory[0]))
    data := memory[int(ctxLen):]

    C.vsc_buffer_init(ctx)
    C.vsc_buffer_use(ctx, (*C.byte)(unsafe.Pointer(&data[0])), capacity)

    return &buffer {
        memory: memory,
        ctx: ctx,
        data: data,
    }, nil
}

func (obj *buffer) getData() []byte {
    newSize := int(C.vsc_buffer_len(obj.ctx))
    if newSize > len(obj.data) {
        panic ("Underlying C buffer corrupt the memory.")
    }
    return obj.data[:newSize]
}

func (obj *buffer) cap() int {
    return int(C.vsc_buffer_capacity(obj.ctx))
}

func (obj *buffer) len() int {
    return int(C.vsc_buffer_len(obj.ctx))
}

/*
* Release underlying C context.
*/
func (obj *buffer) delete() {
    C.vsc_buffer_delete(obj.ctx)
}
