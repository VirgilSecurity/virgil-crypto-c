//  Copyright (C) 2015-2018 Virgil Security Inc.
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

// #cgo CFLAGS: -I${SRCDIR}/../include
// #cgo LDFLAGS: -L${SRCDIR}/../lib -lvsc_common
// #include <virgil/common/vsc_buffer.h>
import "C"
import unsafe "unsafe"

// Buf is needed to pass memory to be written within C
type Buf struct {
    memory []byte
    cbuf *C.vsc_buffer_t
    data []byte
}

// NewBuf allocates memory block of predefined capacity
func NewBuf(capacity int) *Buf {
    if capacity == 0 {
        panic("Buffer with capacity zero is not allowed.");
    }

    ctxLen := int(C.vsc_buffer_ctx_size())
    memory := make([]byte, ctxLen + capacity)
    cbuf := (*C.vsc_buffer_t)(unsafe.Pointer(&memory[0]))
    data := memory[ctxLen:]

    C.vsc_buffer_init(cbuf)
    C.vsc_buffer_use(cbuf, (*C.byte)(unsafe.Pointer(&data[0])), C.size_t(capacity))

    return &Buf{
        memory: memory,
        cbuf: cbuf,
        data: data,
    }
}

// GetData returns as many bytes as were written to buf by C code
func (b *Buf) GetData() []byte {
    newSize := int(C.vsc_buffer_len(b.cbuf))
    if newSize > len(b.data) {
        panic("Underlying C buffer corrupt the memory.")
    }
    return b.data[:newSize]
}

// Cap returns buffer capacity
func (b *Buf) Cap() int {
    return int(C.vsc_buffer_capacity(b.cbuf))
}

// Len returns buffer actual data length
func (b *Buf) Len() int {
    return int(C.vsc_buffer_len(b.cbuf))
}
