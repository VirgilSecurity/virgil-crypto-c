package foundation

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
func PemWrappedLen(title string, dataLen uint) uint {
    titleStr := C.CString(title)
    defer C.free(unsafe.Pointer(titleStr))

    proxyResult := C.vscf_pem_wrapped_len(titleStr, (C.size_t)(dataLen))

    return uint(proxyResult)
}

/*
* Takes binary data and wraps it to the simple PEM format - no
* additional information just header-base64-footer.
* Note, written buffer is NOT null-terminated.
*/
func PemWrap(title string, data []byte) []byte {
    titleStr := C.CString(title)
    defer C.free(unsafe.Pointer(titleStr))

    pemBuf, pemBufErr := newBuffer(int(PemWrappedLen(title, uint(len(data)))))
    if pemBufErr != nil {
        return nil
    }
    defer pemBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_pem_wrap(titleStr, dataData, pemBuf.ctx)

    return pemBuf.getData()
}

/*
* Return length in bytes required to hold unwrapped binary.
*/
func PemUnwrappedLen(pemLen uint) uint {
    proxyResult := C.vscf_pem_unwrapped_len((C.size_t)(pemLen))

    return uint(proxyResult)
}

/*
* Takes PEM data and extract binary data from it.
*/
func PemUnwrap(pem []byte) ([]byte, error) {
    dataBuf, dataBufErr := newBuffer(int(PemUnwrappedLen(uint(len(pem)))))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.delete()
    pemData := helperWrapData (pem)

    proxyResult := C.vscf_pem_unwrap(pemData, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataBuf.getData(), nil
}

/*
* Returns PEM title if PEM data is valid, otherwise - empty data.
*/
func PemTitle(pem []byte) []byte {
    pemData := helperWrapData (pem)

    proxyResult := C.vscf_pem_title(pemData)

    return helperExtractData(proxyResult)
}
