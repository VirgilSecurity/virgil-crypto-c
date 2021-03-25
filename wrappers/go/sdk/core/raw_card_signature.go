package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Represent signature of "raw card content" snapshot.
*/
type RawCardSignature struct {
    cCtx *C.vssc_raw_card_signature_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RawCardSignature) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRawCardSignature() *RawCardSignature {
    ctx := C.vssc_raw_card_signature_new()
    obj := &RawCardSignature {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawCardSignature).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawCardSignatureWithCtx(pointer unsafe.Pointer) *RawCardSignature {
    ctx := (*C.vssc_raw_card_signature_t /*ct2*/)(pointer)
    obj := &RawCardSignature {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawCardSignature).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawCardSignatureCopy(pointer unsafe.Pointer) *RawCardSignature {
    ctx := (*C.vssc_raw_card_signature_t /*ct2*/)(pointer)
    obj := &RawCardSignature {
        cCtx: C.vssc_raw_card_signature_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RawCardSignature).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RawCardSignature) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RawCardSignature) delete() {
    C.vssc_raw_card_signature_delete(obj.cCtx)
}

/*
* Create Raw Card Signature with mandatory properties.
*/
func NewRawCardSignatureWithSignature(signerId string, signature []byte) *RawCardSignature {
    signerIdChar := C.CString(signerId)
    defer C.free(unsafe.Pointer(signerIdChar))
    signerIdStr := C.vsc_str_from_str(signerIdChar)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vssc_raw_card_signature_new_with_signature(signerIdStr, signatureData)

    runtime.KeepAlive(signerId)

    obj := &RawCardSignature {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*RawCardSignature).Delete)
    return obj
}

/*
* Create Raw Card Signature with extra fields.
*
* Note, snapshot is taken from the extra fields.
*/
func NewRawCardSignatureWithExtraFields(signerId string, signature []byte, extraFields *JsonObject) *RawCardSignature {
    signerIdChar := C.CString(signerId)
    defer C.free(unsafe.Pointer(signerIdChar))
    signerIdStr := C.vsc_str_from_str(signerIdChar)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vssc_raw_card_signature_new_with_extra_fields(signerIdStr, signatureData, (*C.vssc_json_object_t)(unsafe.Pointer(extraFields.Ctx())))

    runtime.KeepAlive(signerId)

    runtime.KeepAlive(extraFields)

    obj := &RawCardSignature {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*RawCardSignature).Delete)
    return obj
}

/*
* Return identifier of signer.
*/
func (obj *RawCardSignature) SignerId() string {
    proxyResult := /*pr4*/C.vssc_raw_card_signature_signer_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return signature.
*/
func (obj *RawCardSignature) Signature() []byte {
    proxyResult := /*pr4*/C.vssc_raw_card_signature_signature(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return snaphot of additional data.
*/
func (obj *RawCardSignature) Snapshot() []byte {
    proxyResult := /*pr4*/C.vssc_raw_card_signature_snapshot(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return signed extra fields.
*/
func (obj *RawCardSignature) ExtraFields() *JsonObject {
    proxyResult := /*pr4*/C.vssc_raw_card_signature_extra_fields(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewJsonObjectCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Create raw card signature from JSON representation.
*/
func RawCardSignatureImportFromJson(json *JsonObject) (*RawCardSignature, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)

    proxyResult := /*pr4*/C.vssc_raw_card_signature_import_from_json((*C.vssc_json_object_t)(unsafe.Pointer(json.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(json)

    return NewRawCardSignatureWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Export Raw Card Signature as JSON.
*/
func (obj *RawCardSignature) ExportAsJson() *JsonObject {
    proxyResult := /*pr4*/C.vssc_raw_card_signature_export_as_json(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewJsonObjectWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}
