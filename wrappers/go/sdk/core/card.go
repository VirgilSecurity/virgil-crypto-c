package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Represent Virgil Card.
*
* Virgil Card is a central entity of Virgil Cards Service.
*/
type Card struct {
    cCtx *C.vssc_card_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *Card) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCard() *Card {
    ctx := C.vssc_card_new()
    obj := &Card {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Card).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewCardWithCtx(pointer unsafe.Pointer) *Card {
    ctx := (*C.vssc_card_t /*ct2*/)(pointer)
    obj := &Card {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Card).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewCardCopy(pointer unsafe.Pointer) *Card {
    ctx := (*C.vssc_card_t /*ct2*/)(pointer)
    obj := &Card {
        cCtx: C.vssc_card_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Card).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Card) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Card) delete() {
    C.vssc_card_delete(obj.cCtx)
}

/*
* Create Virgil Card with mandatory properties.
*/
func NewCardWith(rawCard *RawCard, publicKeyId []byte, publicKey foundation.PublicKey) *Card {
    publicKeyIdData := helperWrapData (publicKeyId)

    proxyResult := /*pr4*/C.vssc_card_new_with((*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), publicKeyIdData, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(rawCard)

    runtime.KeepAlive(publicKey)

    obj := &Card {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*Card).Delete)
    return obj
}

/*
* Set previous Card.
*/
func (obj *Card) SetPreviousCard(previousCard *Card) {
    C.vssc_card_set_previous_card(obj.cCtx, (*C.vssc_card_t)(unsafe.Pointer(previousCard.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(previousCard)

    return
}

/*
* Return Card unique identifier.
*/
func (obj *Card) Identifier() string {
    proxyResult := /*pr4*/C.vssc_card_identifier(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return Card identity.
*/
func (obj *Card) Identity() string {
    proxyResult := /*pr4*/C.vssc_card_identity(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return Card public key.
*/
func (obj *Card) PublicKey() (foundation.PublicKey, error) {
    proxyResult := /*pr4*/C.vssc_card_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return foundation.ImplementationWrapPublicKeyCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}

/*
* Return Card public key identifier.
*/
func (obj *Card) PublicKeyId() []byte {
    proxyResult := /*pr4*/C.vssc_card_public_key_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return Card version.
*/
func (obj *Card) Version() string {
    proxyResult := /*pr4*/C.vssc_card_version(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return timestamp of Card creation.
*/
func (obj *Card) CreatedAt() uint {
    proxyResult := /*pr4*/C.vssc_card_created_at(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return Card content snapshot.
*/
func (obj *Card) ContentSnapshot() []byte {
    proxyResult := /*pr4*/C.vssc_card_content_snapshot(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return whether Card is outdated or not.
*/
func (obj *Card) IsOutdated() bool {
    proxyResult := /*pr4*/C.vssc_card_is_outdated(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return identifier of previous card if exists.
*/
func (obj *Card) PreviousCardId() string {
    proxyResult := /*pr4*/C.vssc_card_previous_card_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return whether previous card exists or not.
*/
func (obj *Card) HasPreviousCard() bool {
    proxyResult := /*pr4*/C.vssc_card_has_previous_card(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous card if exists, NULL otherwise.
*/
func (obj *Card) PreviousCard() *Card {
    proxyResult := /*pr4*/C.vssc_card_previous_card(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewCardCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return Card signatures,
*/
func (obj *Card) Signatures() *RawCardSignatureList {
    proxyResult := /*pr4*/C.vssc_card_signatures(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewRawCardSignatureListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return raw card.
*/
func (obj *Card) GetRawCard() *RawCard {
    proxyResult := /*pr4*/C.vssc_card_get_raw_card(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewRawCardCopy(unsafe.Pointer(proxyResult)) /* r5 */
}
