package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handles a list of "password recipient info" class objects.
*/
type PasswordRecipientInfoList struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this PasswordRecipientInfoList) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewPasswordRecipientInfoList () *PasswordRecipientInfoList {
    ctx := C.vscf_password_recipient_info_list_new()
    return &PasswordRecipientInfoList {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPasswordRecipientInfoListWithCtx (ctx *C.vscf_impl_t) *PasswordRecipientInfoList {
    return &PasswordRecipientInfoList {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPasswordRecipientInfoListCopy (ctx *C.vscf_impl_t) *PasswordRecipientInfoList {
    return &PasswordRecipientInfoList {
        ctx: C.vscf_password_recipient_info_list_shallow_copy(ctx),
    }
}

/*
* Return true if given list has item.
*/
func (this PasswordRecipientInfoList) HasItem () bool {
    proxyResult := C.vscf_password_recipient_info_list_has_item(this.ctx)

    return proxyResult //r9
}

/*
* Return list item.
*/
func (this PasswordRecipientInfoList) Item () PasswordRecipientInfo {
    proxyResult := C.vscf_password_recipient_info_list_item(this.ctx)

    return PasswordRecipientInfo(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
*/
func (this PasswordRecipientInfoList) HasNext () bool {
    proxyResult := C.vscf_password_recipient_info_list_has_next(this.ctx)

    return proxyResult //r9
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (this PasswordRecipientInfoList) Next () PasswordRecipientInfoList {
    proxyResult := C.vscf_password_recipient_info_list_next(this.ctx)

    return *NewPasswordRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Return true if list has previous item.
*/
func (this PasswordRecipientInfoList) HasPrev () bool {
    proxyResult := C.vscf_password_recipient_info_list_has_prev(this.ctx)

    return proxyResult //r9
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (this PasswordRecipientInfoList) Prev () PasswordRecipientInfoList {
    proxyResult := C.vscf_password_recipient_info_list_prev(this.ctx)

    return *NewPasswordRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Remove all items.
*/
func (this PasswordRecipientInfoList) Clear () {
    C.vscf_password_recipient_info_list_clear(this.ctx)
}
