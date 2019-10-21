package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Group ticket used to start group session, remove participants or proactive to rotate encryption key.
*/
type GroupSessionTicket struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this GroupSessionTicket) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewGroupSessionTicket () *GroupSessionTicket {
    ctx := C.vscf_group_session_ticket_new()
    return &GroupSessionTicket {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewGroupSessionTicketWithCtx (ctx *C.vscf_impl_t) *GroupSessionTicket {
    return &GroupSessionTicket {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewGroupSessionTicketCopy (ctx *C.vscf_impl_t) *GroupSessionTicket {
    return &GroupSessionTicket {
        ctx: C.vscf_group_session_ticket_shallow_copy(ctx),
    }
}

/*
* Random used to generate keys
*/
func (this GroupSessionTicket) SetRng (rng IRandom) {
    C.vscf_group_session_ticket_release_rng(this.ctx)
    C.vscf_group_session_ticket_use_rng(this.ctx, rng.Ctx())
}

/*
* Setups default dependencies:
* - RNG: CTR DRBG
*/
func (this GroupSessionTicket) SetupDefaults () {
    proxyResult := C.vscf_group_session_ticket_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Set this ticket to start new group session.
*/
func (this GroupSessionTicket) SetupTicketAsNew (sessionId []byte) {
    proxyResult := C.vscf_group_session_ticket_setup_ticket_as_new(this.ctx, WrapData(sessionId))

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Returns message that should be sent to all participants using secure channel.
*/
func (this GroupSessionTicket) GetTicketMessage () GroupSessionMessage {
    proxyResult := C.vscf_group_session_ticket_get_ticket_message(this.ctx)

    return GroupSessionMessage.init(use: proxyResult!) /* r5 */
}
