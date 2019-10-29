package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Simple PEM wrapper.
*/
type Pem struct {
}

/*
* Return length in bytes required to hold wrapped PEM format.
*/
func PemWrappedLen (title string, dataLen uint32) uint32 {
    titleStr := C.CString(title)
    defer C.free(unsafe.Pointer(titleStr))

    proxyResult := /*pr4*/C.vscf_pem_wrapped_len(titleStr/*pa9*/, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Takes binary data and wraps it to the simple PEM format - no
* additional information just header-base64-footer.
* Note, written buffer is NOT null-terminated.
*/
func PemWrap (title string, data []byte) []byte {
    titleStr := C.CString(title)
    defer C.free(unsafe.Pointer(titleStr))

    pemCount := C.ulong(PemWrappedLen(title, uint32(len(data))) /* lg1 */)
    pemMemory := make([]byte, int(C.vsc_buffer_ctx_size() + pemCount))
    pemBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&pemMemory[0]))
    pemData := pemMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(pemBuf)
    C.vsc_buffer_use(pemBuf, (*C.byte)(unsafe.Pointer(&pemData[0])), pemCount)
    defer C.vsc_buffer_delete(pemBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_pem_wrap(titleStr/*pa9*/, dataData, pemBuf)

    return pemData[0:C.vsc_buffer_len(pemBuf)] /* r7 */
}

/*
* Return length in bytes required to hold unwrapped binary.
*/
func PemUnwrappedLen (pemLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_pem_unwrapped_len((C.size_t)(pemLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Takes PEM data and extract binary data from it.
*/
func PemUnwrap (pem []byte) ([]byte, error) {
    dataCount := C.ulong(PemUnwrappedLen(uint32(len(pem))) /* lg1 */)
    dataMemory := make([]byte, int(C.vsc_buffer_ctx_size() + dataCount))
    dataBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&dataMemory[0]))
    dataData := dataMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(dataBuf)
    C.vsc_buffer_use(dataBuf, (*C.byte)(unsafe.Pointer(&dataData[0])), dataCount)
    defer C.vsc_buffer_delete(dataBuf)
    pemData := C.vsc_data((*C.uint8_t)(&pem[0]), C.size_t(len(pem)))

    proxyResult := /*pr4*/C.vscf_pem_unwrap(pemData, dataBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataData[0:C.vsc_buffer_len(dataBuf)] /* r7 */, nil
}

/*
* Returns PEM title if PEM data is valid, otherwise - empty data.
*/
func PemTitle (pem []byte) []byte {
    pemData := C.vsc_data((*C.uint8_t)(&pem[0]), C.size_t(len(pem)))

    proxyResult := /*pr4*/C.vscf_pem_title(pemData)

    return helperDataToBytes(proxyResult) /* r1 */
}
