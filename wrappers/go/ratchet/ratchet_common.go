package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"


/*
* Class with public constants
*/
type RatchetCommon struct {
}
const (
    /*
    * Max plain text length allowed to be encrypted
    */
    RatchetCommonMaxPlainTextLen uint = 30000
    /*
    * Max message length
    */
    RatchetCommonMaxMessageLen uint = 32975
    /*
    * Key pair id length
    */
    RatchetCommonKeyIdLen uint = 8
    /*
    * Participant id length
    */
    RatchetCommonParticipantIdLen uint = 32
    /*
    * Session id length
    */
    RatchetCommonSessionIdLen uint = 32
    /*
    * Max number of group chat participants
    */
    RatchetCommonMaxParticipantsCount uint = 100
    /*
    * Min number of group chat participants
    */
    RatchetCommonMinParticipantsCount uint = 2
    /*
    * Max group message length
    */
    RatchetCommonMaxGroupMessageLen uint = 32918
)
