package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
*/
type Base64 struct {
}

/*
* Calculate length in bytes required to hold an encoded base64 string.
*/
func Base64EncodedLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_base64_encoded_len((C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encode given data to the base64 format.
* Note, written buffer is NOT null-terminated.
*/
func Base64Encode (data []byte) []byte {
    strCount := C.ulong(Base64EncodedLen(uint32(len(data))) /* lg1 */)
    strMemory := make([]byte, int(C.vsc_buffer_ctx_size() + strCount))
    strBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&strMemory[0]))
    strData := strMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(strBuf)
    C.vsc_buffer_use(strBuf, (*C.byte)(unsafe.Pointer(&strData[0])), strCount)
    defer C.vsc_buffer_delete(strBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_base64_encode(dataData, strBuf)

    return strData[0:C.vsc_buffer_len(strBuf)] /* r7 */
}

/*
* Calculate length in bytes required to hold a decoded base64 string.
*/
func Base64DecodedLen (strLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_base64_decoded_len((C.size_t)(strLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Decode given data from the base64 format.
*/
func Base64Decode (str []byte) ([]byte, error) {
    dataCount := C.ulong(Base64DecodedLen(uint32(len(str))) /* lg1 */)
    dataMemory := make([]byte, int(C.vsc_buffer_ctx_size() + dataCount))
    dataBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&dataMemory[0]))
    dataData := dataMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(dataBuf)
    C.vsc_buffer_use(dataBuf, (*C.byte)(unsafe.Pointer(&dataData[0])), dataCount)
    defer C.vsc_buffer_delete(dataBuf)
    strData := C.vsc_data((*C.uint8_t)(&str[0]), C.size_t(len(str)))

    proxyResult := /*pr4*/C.vscf_base64_decode(strData, dataBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataData[0:C.vsc_buffer_len(dataBuf)] /* r7 */, nil
}
