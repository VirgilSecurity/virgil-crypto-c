package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handles a list of "password recipient info" class objects.
*/
type PasswordRecipientInfoList struct {
    cCtx *C.vscf_password_recipient_info_list_t /*ct2*/
}

/* Handle underlying C context. */
func (this PasswordRecipientInfoList) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewPasswordRecipientInfoList () *PasswordRecipientInfoList {
    ctx := C.vscf_password_recipient_info_list_new()
    return &PasswordRecipientInfoList {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPasswordRecipientInfoListWithCtx (ctx *C.vscf_password_recipient_info_list_t /*ct2*/) *PasswordRecipientInfoList {
    return &PasswordRecipientInfoList {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPasswordRecipientInfoListCopy (ctx *C.vscf_password_recipient_info_list_t /*ct2*/) *PasswordRecipientInfoList {
    return &PasswordRecipientInfoList {
        cCtx: C.vscf_password_recipient_info_list_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this PasswordRecipientInfoList) close () {
    C.vscf_password_recipient_info_list_delete(this.cCtx)
}

/*
* Return true if given list has item.
*/
func (this PasswordRecipientInfoList) HasItem () bool {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_list_has_item(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (this PasswordRecipientInfoList) Item () *PasswordRecipientInfo {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_list_item(this.cCtx)

    return newPasswordRecipientInfoWithCtx(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
*/
func (this PasswordRecipientInfoList) HasNext () bool {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_list_has_next(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (this PasswordRecipientInfoList) Next () *PasswordRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_list_next(this.cCtx)

    return newPasswordRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Return true if list has previous item.
*/
func (this PasswordRecipientInfoList) HasPrev () bool {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_list_has_prev(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (this PasswordRecipientInfoList) Prev () *PasswordRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_list_prev(this.cCtx)

    return newPasswordRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Remove all items.
*/
func (this PasswordRecipientInfoList) Clear () {
    C.vscf_password_recipient_info_list_clear(this.cCtx)

    return
}
