package ratchet

import (
	"testing"

	"github.com/VirgilSecurity/virgil-crypto-c/wrappers/go/foundation"
	"github.com/stretchr/testify/require"
)

func TestRatchetMessage_GetType_Prekey(t *testing.T) {
	alice, _, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()

	// The first message from an initiator is always a prekey message.
	require.Equal(t, MsgTypePrekey, firstMsg.GetType())
}

func TestRatchetMessage_GetType_Regular(t *testing.T) {
	alice, bob, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()
	defer bob.Delete()

	_, err := bob.Decrypt(firstMsg)
	require.NoError(t, err)

	// After decrypting the first prekey message, bob's next message is regular.
	response, err := bob.Encrypt([]byte("regular"))
	require.NoError(t, err)
	require.Equal(t, MsgTypeRegular, response.GetType())

	// Alice's next message after receiving the response is also regular.
	_, err = alice.Decrypt(response)
	require.NoError(t, err)

	next, err := alice.Encrypt([]byte("also regular"))
	require.NoError(t, err)
	require.Equal(t, MsgTypeRegular, next.GetType())
}

func TestRatchetMessage_GetCounter(t *testing.T) {
	alice, bob, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()
	defer bob.Delete()

	require.Equal(t, uint32(0), firstMsg.GetCounter())

	_, err := bob.Decrypt(firstMsg)
	require.NoError(t, err)

	// Second message from alice increments the counter.
	second, err := alice.Encrypt([]byte("second"))
	require.NoError(t, err)
	require.Equal(t, uint32(1), second.GetCounter())
}

func TestRatchetMessage_Serialize_Deserialize(t *testing.T) {
	_, _, firstMsg := setupSessionPairNoOTK(t)

	data := firstMsg.Serialize()
	require.NotEmpty(t, data)

	deserialized, err := firstMsg.Deserialize(data)
	require.NoError(t, err)
	require.NotNil(t, deserialized)
	defer deserialized.Delete()

	require.Equal(t, firstMsg.GetType(), deserialized.GetType())
	require.Equal(t, firstMsg.GetCounter(), deserialized.GetCounter())
	require.Equal(t, firstMsg.GetSenderIdentityKeyId(), deserialized.GetSenderIdentityKeyId())
	require.Equal(t, firstMsg.GetReceiverIdentityKeyId(), deserialized.GetReceiverIdentityKeyId())
	require.Equal(t, firstMsg.GetReceiverLongTermKeyId(), deserialized.GetReceiverLongTermKeyId())
}

func TestRatchetMessage_KeyIds_Prekey_NoOTK(t *testing.T) {
	_, _, firstMsg := setupSessionPairNoOTK(t)

	aliceID := keyID(0x10)
	bobID := keyID(0x20)
	bobLtID := keyID(0x30)

	require.Equal(t, aliceID, firstMsg.GetSenderIdentityKeyId())
	require.Equal(t, bobID, firstMsg.GetReceiverIdentityKeyId())
	require.Equal(t, bobLtID, firstMsg.GetReceiverLongTermKeyId())
	// No one-time key: one-time key ID should be empty.
	require.Empty(t, firstMsg.GetReceiverOneTimeKeyId())
}

func TestRatchetMessage_KeyIds_Prekey_WithOTK(t *testing.T) {
	kp := newKeyProvider()

	aliceIdentPriv, _ := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	aliceIdentPub, _ := aliceIdentPriv.ExtractPublicKey()
	bobIdentPriv, _ := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	bobIdentPub, _ := bobIdentPriv.ExtractPublicKey()
	bobLtPriv, _ := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	bobLtPub, _ := bobLtPriv.ExtractPublicKey()
	bobOtPriv, _ := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	bobOtPub, _ := bobOtPriv.ExtractPublicKey()

	aliceID := keyID(0x01)
	bobID := keyID(0x02)
	bobLtID := keyID(0x03)
	bobOtID := keyID(0x04)

	alice := newRatchetSession()
	defer alice.Delete()
	_ = alice.Initiate(aliceIdentPriv, aliceID, bobIdentPub, bobID, bobLtPub, bobLtID, bobOtPub, bobOtID)

	msg, _ := alice.Encrypt([]byte("otk test"))
	require.Equal(t, aliceID, msg.GetSenderIdentityKeyId())
	require.Equal(t, bobID, msg.GetReceiverIdentityKeyId())
	require.Equal(t, bobLtID, msg.GetReceiverLongTermKeyId())
	require.Equal(t, bobOtID, msg.GetReceiverOneTimeKeyId())

	// Verify bob can respond using the key IDs from the message.
	bob := newRatchetSession()
	defer bob.Delete()
	_ = bob.Respond(aliceIdentPub, bobIdentPriv, bobLtPriv, bobOtPriv, msg)
	got, err := bob.Decrypt(msg)
	require.NoError(t, err)
	require.Equal(t, []byte("otk test"), got)
}

func TestRatchetMessage_SerializeLen(t *testing.T) {
	_, _, firstMsg := setupSessionPairNoOTK(t)

	serLen := firstMsg.SerializeLen()
	data := firstMsg.Serialize()
	require.Equal(t, int(serLen), len(data))
}
