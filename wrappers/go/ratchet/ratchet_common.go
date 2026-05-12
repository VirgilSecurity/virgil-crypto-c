package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"


/*
* Class with public constants
*/
type RatchetCommon struct {
}
const (
    RatchetCommonMaxPlainTextLen uint = 30000
    RatchetCommonMaxMessageLen uint = 35583
    RatchetCommonKeyIdLen uint = 8
    RatchetCommonParticipantIdLen uint = 32
    RatchetCommonSessionIdLen uint = 32
    RatchetCommonMaxParticipantsCount uint = 100
    RatchetCommonMinParticipantsCount uint = 2
    RatchetCommonMaxGroupMessageLen uint = 32918
)
