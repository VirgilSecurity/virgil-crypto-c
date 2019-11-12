package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
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

    pemBuf, pemBufErr := bufferNewBuffer(int(PemWrappedLen(title, uint32(len(data))) /* lg1 */))
    if pemBufErr != nil {
        return nil
    }
    defer pemBuf.Delete()
    dataData := helperWrapData (data)

    C.vscf_pem_wrap(titleStr/*pa9*/, dataData, pemBuf.ctx)

    return pemBuf.getData() /* r7 */
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
    dataBuf, dataBufErr := bufferNewBuffer(int(PemUnwrappedLen(uint32(len(pem))) /* lg1 */))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.Delete()
    pemData := helperWrapData (pem)

    proxyResult := /*pr4*/C.vscf_pem_unwrap(pemData, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataBuf.getData() /* r7 */, nil
}

/*
* Returns PEM title if PEM data is valid, otherwise - empty data.
*/
func PemTitle (pem []byte) []byte {
    pemData := helperWrapData (pem)

    proxyResult := /*pr4*/C.vscf_pem_title(pemData)

    return helperExtractData(proxyResult) /* r1 */
}
