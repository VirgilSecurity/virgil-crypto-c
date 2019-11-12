package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Group ticket used to start group session, remove participants or proactive to rotate encryption key.
*/
type GroupSessionTicket struct {
    cCtx *C.vscf_group_session_ticket_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *GroupSessionTicket) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewGroupSessionTicket () *GroupSessionTicket {
    ctx := C.vscf_group_session_ticket_new()
    return &GroupSessionTicket {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionTicketWithCtx (ctx *C.vscf_group_session_ticket_t /*ct2*/) *GroupSessionTicket {
    return &GroupSessionTicket {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionTicketCopy (ctx *C.vscf_group_session_ticket_t /*ct2*/) *GroupSessionTicket {
    return &GroupSessionTicket {
        cCtx: C.vscf_group_session_ticket_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *GroupSessionTicket) Delete () {
    C.vscf_group_session_ticket_delete(obj.cCtx)
}

/*
* Random used to generate keys
*/
func (obj *GroupSessionTicket) SetRng (rng IRandom) {
    C.vscf_group_session_ticket_release_rng(obj.cCtx)
    C.vscf_group_session_ticket_use_rng(obj.cCtx, (*C.vscf_impl_t)(rng.ctx()))
}

/*
* Setups default dependencies:
* - RNG: CTR DRBG
*/
func (obj *GroupSessionTicket) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_group_session_ticket_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Set this ticket to start new group session.
*/
func (obj *GroupSessionTicket) SetupTicketAsNew (sessionId []byte) error {
    sessionIdData := helperWrapData (sessionId)

    proxyResult := /*pr4*/C.vscf_group_session_ticket_setup_ticket_as_new(obj.cCtx, sessionIdData)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Returns message that should be sent to all participants using secure channel.
*/
func (obj *GroupSessionTicket) GetTicketMessage () *GroupSessionMessage {
    proxyResult := /*pr4*/C.vscf_group_session_ticket_get_ticket_message(obj.cCtx)

    return newGroupSessionMessageWithCtx(proxyResult) /* r5 */
}
