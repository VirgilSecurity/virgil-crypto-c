package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"
import "runtime"


/*
* Container for array of participants' info
*/
type RatchetGroupParticipantsInfo struct {
    cCtx *C.vscr_ratchet_group_participants_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RatchetGroupParticipantsInfo) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRatchetGroupParticipantsInfo() *RatchetGroupParticipantsInfo {
    ctx := C.vscr_ratchet_group_participants_info_new()
    obj := &RatchetGroupParticipantsInfo {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *RatchetGroupParticipantsInfo) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetGroupParticipantsInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupParticipantsInfoWithCtx(ctx *C.vscr_ratchet_group_participants_info_t /*ct2*/) *RatchetGroupParticipantsInfo {
    obj := &RatchetGroupParticipantsInfo {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *RatchetGroupParticipantsInfo) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetGroupParticipantsInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupParticipantsInfoCopy(ctx *C.vscr_ratchet_group_participants_info_t /*ct2*/) *RatchetGroupParticipantsInfo {
    obj := &RatchetGroupParticipantsInfo {
        cCtx: C.vscr_ratchet_group_participants_info_shallow_copy(ctx),
    }
    //runtime.SetFinalizer(obj, func (o *RatchetGroupParticipantsInfo) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetGroupParticipantsInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupParticipantsInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupParticipantsInfo) delete() {
    C.vscr_ratchet_group_participants_info_delete(obj.cCtx)
}

/*
* Creates new array for size elements
*/
func NewRatchetGroupParticipantsInfoSize(size uint32) *RatchetGroupParticipantsInfo {
    proxyResult := /*pr4*/C.vscr_ratchet_group_participants_info_new_size((C.uint)(size)/*pa10*/)

    obj := &RatchetGroupParticipantsInfo {
        cCtx: proxyResult,
    }
    //runtime.SetFinalizer(obj, func (o *RatchetGroupParticipantsInfo) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetGroupParticipantsInfo).Delete)
    return obj
}

/*
* Add participant info
*/
func (obj *RatchetGroupParticipantsInfo) AddParticipant(id []byte, pubKey []byte) error {
    idData := helperWrapData (id)
    pubKeyData := helperWrapData (pubKey)

    proxyResult := /*pr4*/C.vscr_ratchet_group_participants_info_add_participant(obj.cCtx, idData, pubKeyData)

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}
