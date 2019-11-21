package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"
import "runtime"
import foundation "virgil/foundation"


/*
* Group ticket used to start group session or change participants.
*/
type RatchetGroupTicket struct {
    cCtx *C.vscr_ratchet_group_ticket_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RatchetGroupTicket) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRatchetGroupTicket() *RatchetGroupTicket {
    ctx := C.vscr_ratchet_group_ticket_new()
    obj := &RatchetGroupTicket {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *RatchetGroupTicket) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetGroupTicket).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupTicketWithCtx(ctx *C.vscr_ratchet_group_ticket_t /*ct2*/) *RatchetGroupTicket {
    obj := &RatchetGroupTicket {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *RatchetGroupTicket) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetGroupTicket).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupTicketCopy(ctx *C.vscr_ratchet_group_ticket_t /*ct2*/) *RatchetGroupTicket {
    obj := &RatchetGroupTicket {
        cCtx: C.vscr_ratchet_group_ticket_shallow_copy(ctx),
    }
    //runtime.SetFinalizer(obj, func (o *RatchetGroupTicket) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetGroupTicket).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupTicket) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupTicket) delete() {
    C.vscr_ratchet_group_ticket_delete(obj.cCtx)
}

/*
* Random used to generate keys
*/
func (obj *RatchetGroupTicket) SetRng(rng foundation.Random) {
    C.vscr_ratchet_group_ticket_release_rng(obj.cCtx)
    C.vscr_ratchet_group_ticket_use_rng(obj.cCtx, (*C.vscf_impl_t)(rng.(context).ctx()))

    runtime.KeepAlive(rng)
    runtime.KeepAlive(obj)
}

/*
* Setups default dependencies:
* - RNG: CTR DRBG
*/
func (obj *RatchetGroupTicket) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscr_ratchet_group_ticket_setup_defaults(obj.cCtx)

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Set this ticket to start new group session.
*/
func (obj *RatchetGroupTicket) SetupTicketAsNew(sessionId []byte) error {
    sessionIdData := helperWrapData (sessionId)

    proxyResult := /*pr4*/C.vscr_ratchet_group_ticket_setup_ticket_as_new(obj.cCtx, sessionIdData)

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Returns message that should be sent to all participants using secure channel.
*/
func (obj *RatchetGroupTicket) GetTicketMessage() *RatchetGroupMessage {
    proxyResult := /*pr4*/C.vscr_ratchet_group_ticket_get_ticket_message(obj.cCtx)

    runtime.KeepAlive(obj)

    return newRatchetGroupMessageCopy(proxyResult) /* r5 */
}
