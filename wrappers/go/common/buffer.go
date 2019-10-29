//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package common

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #include <virgil/crypto/common/vsc_common_public.h>
import "C"
import unsafe "unsafe"

// Buf is needed to pass memory to be written within C
type Buffer struct {
    memory []byte
    ctx *C.vsc_buffer_t
    data []byte
}

// NewBuffer allocates memory block of predefined capacity
func NewBuffer(cap int) *Buffer {
    capacity := C.size_t(cap)
    if capacity == 0 {
        panic("Buffer with zero capacity is not allowed.");
    }

    ctxLen := C.vsc_buffer_ctx_size()
    memory := make([]byte, int(ctxLen + capacity))
    ctx := (*C.vsc_buffer_t)(unsafe.Pointer(&memory[0]))
    data := memory[int(ctxLen):]

    C.vsc_buffer_init(ctx)
    C.vsc_buffer_use(ctx, (*C.byte)(unsafe.Pointer(&data[0])), capacity)

    return &Buffer {
        memory: memory,
        ctx: ctx,
        data: data,
    }
}

// GetData returns as many bytes as were written to buf by C code
func (b *Buffer) GetData() []byte {
    newSize := int(C.vsc_buffer_len(b.ctx))
    if newSize > len(b.data) {
        panic("Underlying C buffer corrupt the memory.")
    }
    return b.data[:newSize]
}

// Cap returns buffer capacity
func (b *Buffer) Cap() int {
    return int(C.vsc_buffer_capacity(b.ctx))
}

// Len returns buffer actual data length
func (b *Buffer) Len() int {
    return int(C.vsc_buffer_len(b.ctx))
}

// Len returns buffer actual data length
func (b *Buffer) Clear() {
    //FIXME
    C.vsc_buffer_delete(b.ctx)
}
