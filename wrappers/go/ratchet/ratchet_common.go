package ratchet

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_ratchet -lvsc_ratchet_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"


/*
* Class with public constants
*/
type RatchetCommon struct {
}

/*
* Max plain text length allowed to be encrypted
*/
func RatchetCommonGetMaxPlainTextLen () uint32 {
    return 30000
}

/*
* Max message length
*/
func RatchetCommonGetMaxMessageLen () uint32 {
    return 32975
}

/*
* Key pair id length
*/
func RatchetCommonGetKeyIdLen () uint32 {
    return 8
}

/*
* Participant id length
*/
func RatchetCommonGetParticipantIdLen () uint32 {
    return 32
}

/*
* Session id length
*/
func RatchetCommonGetSessionIdLen () uint32 {
    return 32
}

/*
* Max number of group chat participants
*/
func RatchetCommonGetMaxParticipantsCount () uint32 {
    return 100
}

/*
* Min number of group chat participants
*/
func RatchetCommonGetMinParticipantsCount () uint32 {
    return 2
}

/*
* Max group message length
*/
func RatchetCommonGetMaxGroupMessageLen () uint32 {
    return 32918
}
