package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Prvodes Base64URL encoding and decoding suitable for JWT.
*/
type Base64Url struct {
}

/*
* Calculate length in bytes required to hold an encoded base64url string.
*/
func Base64UrlEncodedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vssc_base64_url_encoded_len((C.size_t)(dataLen)/*pa10*/)

    return uint(proxyResult) /* r9 */
}

/*
* Encode given data to the base64url format.
* Note, written buffer is NOT null-terminated.
*/
func Base64UrlEncode(data []byte) string {
    strBuf := C.vsc_str_buffer_new_with_capacity((C.size_t)(Base64UrlEncodedLen(uint(len(data))) /* lg1 */))
    defer C.vsc_str_buffer_delete(strBuf)
    dataData := helperWrapData (data)

    C.vssc_base64_url_encode(dataData, strBuf)

    return C.GoString(C.vsc_str_buffer_chars(strBuf)) /* r7.1 */
}

/*
* Calculate length in bytes required to hold a decoded base64url string.
*/
func Base64UrlDecodedLen(strLen uint) uint {
    proxyResult := /*pr4*/C.vssc_base64_url_decoded_len((C.size_t)(strLen)/*pa10*/)

    return uint(proxyResult) /* r9 */
}

/*
* Decode given data from the base64url format.
*/
func Base64UrlDecode(str string) ([]byte, error) {
    strChar := C.CString(str)
    defer C.free(unsafe.Pointer(strChar))
    strStr := C.vsc_str_from_str(strChar)

    dataBuf, dataBufErr := newBuffer(int(Base64UrlDecodedLen(uint(len(str))) /* lg1 */))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.delete()


    proxyResult := /*pr4*/C.vssc_base64_url_decode(strStr, dataBuf.ctx)

    err := CoreSdkErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(str)

    return dataBuf.getData() /* r7 */, nil
}
