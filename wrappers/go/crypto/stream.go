/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package crypto

import (
	"bytes"
	"errors"
	"io"

	"virgil/foundation"
)

func NewEncryptWriter(w io.WriteCloser, cipher *foundation.RecipientCipher) *EncryptWriter {
	return &EncryptWriter{
		w:           w,
		cipher:      cipher,
		writeHeader: true,
	}
}

type EncryptWriter struct {
	w           io.WriteCloser
	writeHeader bool
	cipher      *foundation.RecipientCipher
}

func (sw *EncryptWriter) Write(d []byte) (int, error) {
	if sw.writeHeader {
		if _, err := sw.w.Write(sw.cipher.PackMessageInfo()); err != nil {
			return 0, err
		}
		sw.writeHeader = false
	}
	buf, err := sw.cipher.ProcessEncryption(d)
	if err != nil {
		return 0, err
	}
	if n, err := sw.w.Write(buf); err != nil {
		return n, err
	}
	return len(d), nil
}

func (sw *EncryptWriter) Close() error {
	f, err := sw.cipher.FinishEncryption()
	if err != nil {
		return err
	}
	if _, err := sw.w.Write(f); err != nil {
		return err
	}
	return sw.w.Close()
}

func NewDecryptReader(r io.Reader, cipher *foundation.RecipientCipher) *DecryptReader {
	return &DecryptReader{
		r:        r,
		buf:      bytes.NewBuffer(nil),
		cipher:   cipher,
		finished: false,
	}
}

type DecryptReader struct {
	r        io.Reader
	buf      *bytes.Buffer
	finished bool
	cipher   *foundation.RecipientCipher
}

func (dr *DecryptReader) Read(d []byte) (int, error) {
	var buf []byte
	n, err := dr.r.Read(d)
	if n > 0 {
		buf, err = dr.cipher.ProcessDecryption(d[:n])
		if err != nil {
			return 0, err
		}
	} else if errors.Is(err, io.EOF) && !dr.finished {
		buf, err = dr.cipher.FinishDecryption()
		if err != nil {
			return 0, err
		}
		dr.finished = true
	}

	if _, err = dr.buf.Write(buf); err != nil {
		return 0, err
	}

	if dr.buf.Len() > 0 {
		return dr.buf.Read(d)
	}

	// check if cipher return 0 bytes
	if n > 0 {
		return 0, nil
	}
	return 0, io.EOF
}

func NopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopCloser{w}
}

type nopCloser struct {
	io.Writer
}

func (c *nopCloser) Close() error { return nil }
