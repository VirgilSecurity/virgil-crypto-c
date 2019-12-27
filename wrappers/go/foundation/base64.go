package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
*/
type Base64 struct {
}

/*
* Calculate length in bytes required to hold an encoded base64 string.
*/
func Base64EncodedLen(dataLen int) int {
    proxyResult := /*pr4*/C.vscf_base64_encoded_len((C.size_t)(dataLen)/*pa10*/)

    return int(proxyResult) /* r9 */
}

/*
* Encode given data to the base64 format.
* Note, written buffer is NOT null-terminated.
*/
func Base64Encode(data []byte) []byte {
    strBuf, strBufErr := bufferNewBuffer(int(Base64EncodedLen(len(data)) /* lg1 */))
    if strBufErr != nil {
        return nil
    }
    defer strBuf.Delete()
    dataData := helperWrapData (data)

    C.vscf_base64_encode(dataData, strBuf.ctx)

    return strBuf.getData() /* r7 */
}

/*
* Calculate length in bytes required to hold a decoded base64 string.
*/
func Base64DecodedLen(strLen int) int {
    proxyResult := /*pr4*/C.vscf_base64_decoded_len((C.size_t)(strLen)/*pa10*/)

    return int(proxyResult) /* r9 */
}

/*
* Decode given data from the base64 format.
*/
func Base64Decode(str []byte) ([]byte, error) {
    dataBuf, dataBufErr := bufferNewBuffer(int(Base64DecodedLen(len(str)) /* lg1 */))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.Delete()
    strData := helperWrapData (str)

    proxyResult := /*pr4*/C.vscf_base64_decode(strData, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataBuf.getData() /* r7 */, nil
}
