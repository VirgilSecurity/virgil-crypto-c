package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Group chat encryption session.
*/
type GroupSession struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this GroupSession) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewGroupSession () *GroupSession {
    ctx := C.vscf_group_session_new()
    return &GroupSession {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewGroupSessionWithCtx (ctx *C.vscf_impl_t) *GroupSession {
    return &GroupSession {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewGroupSessionCopy (ctx *C.vscf_impl_t) *GroupSession {
    return &GroupSession {
        ctx: C.vscf_group_session_shallow_copy(ctx),
    }
}

/*
* Sender id len
*/
func (this GroupSession) getSenderIdLen () int32 {
    return 32
}

/*
* Max plain text len
*/
func (this GroupSession) getMaxPlainTextLen () int32 {
    return 30000
}

/*
* Max epochs count
*/
func (this GroupSession) getMaxEpochsCount () int32 {
    return 50
}

/*
* Salt size
*/
func (this GroupSession) getSaltSize () int32 {
    return 32
}

/*
* Random
*/
func (this GroupSession) SetRng (rng IRandom) {
    C.vscf_group_session_release_rng(this.ctx)
    C.vscf_group_session_use_rng(this.ctx, rng.Ctx())
}

/*
* Returns current epoch.
*/
func (this GroupSession) GetCurrentEpoch () uint32 {
    proxyResult := C.vscf_group_session_get_current_epoch(this.ctx)

    return proxyResult //r9
}

/*
* Setups default dependencies:
* - RNG: CTR DRBG
*/
func (this GroupSession) SetupDefaults () {
    proxyResult := C.vscf_group_session_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Returns session id.
*/
func (this GroupSession) GetSessionId () []byte {
    proxyResult := C.vscf_group_session_get_session_id(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
* Epoch message should be encrypted and signed by trusted group chat member (admin).
*/
func (this GroupSession) AddEpoch (message GroupSessionMessage) {
    proxyResult := C.vscf_group_session_add_epoch(this.ctx, message.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Encrypts data
*/
func (this GroupSession) Encrypt (plainText []byte, privateKey IPrivateKey) GroupSessionMessage {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_group_session_encrypt(this.ctx, WrapData(plainText), privateKey.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewGroupSessionMessageWithCtx(proxyResult) /* r6 */
}

/*
* Calculates size of buffer sufficient to store decrypted message
*/
func (this GroupSession) DecryptLen (message GroupSessionMessage) int32 {
    proxyResult := C.vscf_group_session_decrypt_len(this.ctx, message.Ctx())

    return proxyResult //r9
}

/*
* Decrypts message
*/
func (this GroupSession) Decrypt (message GroupSessionMessage, publicKey IPublicKey) []byte {
    plainTextCount := this.DecryptLen(message) /* lg2 */
    plainTextBuf := NewBuffer(plainTextCount)
    defer plainTextBuf.Clear()


    proxyResult := C.vscf_group_session_decrypt(this.ctx, message.Ctx(), publicKey.Ctx(), plainTextBuf)

    FoundationErrorHandleStatus(proxyResult)

    return plainTextBuf.GetData() /* r7 */
}

/*
* Creates ticket with new key for removing participants or proactive to rotate encryption key.
*/
func (this GroupSession) CreateGroupTicket () GroupSessionTicket {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_group_session_create_group_ticket(this.ctx, &error)

    FoundationErrorHandleStatus(error.status)

    return *NewGroupSessionTicketWithCtx(proxyResult) /* r6 */
}
