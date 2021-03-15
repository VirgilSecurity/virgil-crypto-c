package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Represent model in binary form which can have signatures and corresponds to Virgil Cards Service model.
*/
type RawCard struct {
    cCtx *C.vssc_raw_card_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RawCard) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRawCard() *RawCard {
    ctx := C.vssc_raw_card_new()
    obj := &RawCard {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawCard).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRawCardWithCtx(ctx *C.vssc_raw_card_t /*ct2*/) *RawCard {
    obj := &RawCard {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawCard).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRawCardCopy(ctx *C.vssc_raw_card_t /*ct2*/) *RawCard {
    obj := &RawCard {
        cCtx: C.vssc_raw_card_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RawCard).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RawCard) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RawCard) delete() {
    C.vssc_raw_card_delete(obj.cCtx)
}

/*
* Create raw card with mandatory info.
*/
func NewRawCardWith(identity string, publicKey []byte, createdAt uint) *RawCard {
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)
    publicKeyData := helperWrapData (publicKey)

    proxyResult := /*pr4*/C.vssc_raw_card_new_with(identityStr, publicKeyData, (C.size_t)(createdAt)/*pa10*/)

    runtime.KeepAlive(identity)

    obj := &RawCard {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*RawCard).Delete)
    return obj
}

/*
* Create raw card from JSON representation.
*/
func RawCardImportFromJson(json *JsonObject) (*RawCard, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)

    proxyResult := /*pr4*/C.vssc_raw_card_import_from_json((*C.vssc_json_object_t)(unsafe.Pointer(json.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(json)

    return newRawCardWithCtx(proxyResult) /* r6 */, nil
}

/*
* Export Raw Card as JSON.
*/
func (obj *RawCard) ExportAsJson() *JsonObject {
    proxyResult := /*pr4*/C.vssc_raw_card_export_as_json(obj.cCtx)

    runtime.KeepAlive(obj)

    return newJsonObjectWithCtx(proxyResult) /* r6 */
}

/*
* Set optional previous card identifier.
*
* Note, previous card identity and the current one should be the same.
*/
func (obj *RawCard) SetPreviousCardId(previousCardId string) {
    previousCardIdChar := C.CString(previousCardId)
    defer C.free(unsafe.Pointer(previousCardIdChar))
    previousCardIdStr := C.vsc_str_from_str(previousCardIdChar)

    C.vssc_raw_card_set_previous_card_id(obj.cCtx, previousCardIdStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(previousCardId)

    return
}

/*
* Set optional card type.
*/
func (obj *RawCard) SetCardType(cardType string) {
    cardTypeChar := C.CString(cardType)
    defer C.free(unsafe.Pointer(cardTypeChar))
    cardTypeStr := C.vsc_str_from_str(cardTypeChar)

    C.vssc_raw_card_set_card_type(obj.cCtx, cardTypeStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(cardType)

    return
}

/*
* Add new signature.
*/
func (obj *RawCard) AddSignature(signature *RawCardSignature) {
    C.vssc_raw_card_add_signature(obj.cCtx, (*C.vssc_raw_card_signature_t)(unsafe.Pointer(signature.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(signature)

    return
}

/*
* Set whether a Card is outdated or not.
*/
func (obj *RawCard) SetIsOutdated(isOutdated bool) {
    C.vssc_raw_card_set_is_outdated(obj.cCtx, (C.bool)(isOutdated)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/*
* Return version of Card.
*/
func (obj *RawCard) Version() string {
    proxyResult := /*pr4*/C.vssc_raw_card_version(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return identity of Card.
*/
func (obj *RawCard) Identity() string {
    proxyResult := /*pr4*/C.vssc_raw_card_identity(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return Public Key data of Card.
*
* Note, public key can be empty.
*/
func (obj *RawCard) PublicKey() []byte {
    proxyResult := /*pr4*/C.vssc_raw_card_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return date of Card creation.
*/
func (obj *RawCard) CreatedAt() uint {
    proxyResult := /*pr4*/C.vssc_raw_card_created_at(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return whether Card is outdated or not.
*/
func (obj *RawCard) IsOutdated() bool {
    proxyResult := /*pr4*/C.vssc_raw_card_is_outdated(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return identifier of previous Card with same identity.
*
* Note, return empty string if there is no previous card.
*/
func (obj *RawCard) PreviousCardId() string {
    proxyResult := /*pr4*/C.vssc_raw_card_previous_card_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return Card's content snapshot.
*/
func (obj *RawCard) ContentSnapshot() []byte {
    proxyResult := /*pr4*/C.vssc_raw_card_content_snapshot(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return Card's signatures.
*/
func (obj *RawCard) Signatures() *RawCardSignatureList {
    proxyResult := /*pr4*/C.vssc_raw_card_signatures(obj.cCtx)

    runtime.KeepAlive(obj)

    return newRawCardSignatureListCopy(proxyResult) /* r5 */
}

/*
* This method invalidates content snapshot.
* It should be called when content is modified.
*/
func (obj *RawCard) InvalidateContentSnapshot() {
    C.vssc_raw_card_invalidate_content_snapshot(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}
