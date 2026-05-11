package ratchet

import (
	"strings"
	"testing"

	"github.com/VirgilSecurity/virgil-crypto-c/wrappers/go/foundation"
	"github.com/stretchr/testify/require"
)

// newKeyProvider returns an initialized KeyProvider using foundation defaults.
func newKeyProvider() *foundation.KeyProvider {
	kp := foundation.NewKeyProvider()
	_ = kp.SetupDefaults()
	return kp
}

// newRatchetSession returns an initialized RatchetSession.
func newRatchetSession() *RatchetSession {
	s := NewRatchetSession()
	_ = s.SetupDefaults()
	return s
}

// keyID returns a deterministic 8-byte key ID for test use.
func keyID(seed byte) []byte {
	id := make([]byte, RatchetCommonKeyIdLen)
	for i := range id {
		id[i] = seed + byte(i)
	}
	return id
}

// setupSessionPair creates a linked initiator/responder session pair using
// only an identity key pair and a long-term key pair (no one-time key).
// Returns alice's session, bob's session, and the initial prekey message
// so callers can exercise the first decrypt immediately.
func setupSessionPairNoOTK(t *testing.T) (alice, bob *RatchetSession, firstMsg *RatchetMessage) {
	t.Helper()
	kp := newKeyProvider()

	aliceIdentPriv, err := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	require.NoError(t, err)
	aliceIdentPub, err := aliceIdentPriv.ExtractPublicKey()
	require.NoError(t, err)

	bobIdentPriv, err := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	require.NoError(t, err)
	bobIdentPub, err := bobIdentPriv.ExtractPublicKey()
	require.NoError(t, err)

	bobLtPriv, err := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	require.NoError(t, err)
	bobLtPub, err := bobLtPriv.ExtractPublicKey()
	require.NoError(t, err)

	aliceID := keyID(0x10)
	bobID := keyID(0x20)
	bobLtID := keyID(0x30)

	alice = newRatchetSession()
	err = alice.InitiateNoOneTimeKey(aliceIdentPriv, aliceID, bobIdentPub, bobID, bobLtPub, bobLtID)
	require.NoError(t, err)

	firstMsg, err = alice.Encrypt([]byte("first"))
	require.NoError(t, err)

	bob = newRatchetSession()
	err = bob.RespondNoOneTimeKey(aliceIdentPub, bobIdentPriv, bobLtPriv, firstMsg)
	require.NoError(t, err)

	return alice, bob, firstMsg
}

func TestNewRatchetSession(t *testing.T) {
	s := NewRatchetSession()
	require.NotNil(t, s)
	s.Delete()
}

func TestSetupDefaults(t *testing.T) {
	s := NewRatchetSession()
	defer s.Delete()
	require.NoError(t, s.SetupDefaults())
}

func TestInitiateNoOneTimeKey_FullRoundTrip(t *testing.T) {
	alice, bob, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()
	defer bob.Delete()

	// Bob decrypts Alice's first message.
	plaintext, err := bob.Decrypt(firstMsg)
	require.NoError(t, err)
	require.Equal(t, []byte("first"), plaintext)

	// Bob sends a reply.
	replyMsg, err := bob.Encrypt([]byte("reply"))
	require.NoError(t, err)

	// Alice decrypts the reply.
	replyText, err := alice.Decrypt(replyMsg)
	require.NoError(t, err)
	require.Equal(t, []byte("reply"), replyText)
}

func TestInitiate_WithOneTimeKey_FullRoundTrip(t *testing.T) {
	kp := newKeyProvider()

	aliceIdentPriv, err := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	require.NoError(t, err)
	aliceIdentPub, err := aliceIdentPriv.ExtractPublicKey()
	require.NoError(t, err)

	bobIdentPriv, err := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	require.NoError(t, err)
	bobIdentPub, err := bobIdentPriv.ExtractPublicKey()
	require.NoError(t, err)

	bobLtPriv, err := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	require.NoError(t, err)
	bobLtPub, err := bobLtPriv.ExtractPublicKey()
	require.NoError(t, err)

	bobOtPriv, err := kp.GeneratePrivateKey(foundation.AlgIdCurve25519)
	require.NoError(t, err)
	bobOtPub, err := bobOtPriv.ExtractPublicKey()
	require.NoError(t, err)

	aliceID := keyID(0x01)
	bobID := keyID(0x02)
	bobLtID := keyID(0x03)
	bobOtID := keyID(0x04)

	alice := newRatchetSession()
	defer alice.Delete()
	err = alice.Initiate(aliceIdentPriv, aliceID, bobIdentPub, bobID, bobLtPub, bobLtID, bobOtPub, bobOtID)
	require.NoError(t, err)

	initMsg, err := alice.Encrypt([]byte("hello with OTK"))
	require.NoError(t, err)

	bob := newRatchetSession()
	defer bob.Delete()
	err = bob.Respond(aliceIdentPub, bobIdentPriv, bobLtPriv, bobOtPriv, initMsg)
	require.NoError(t, err)

	plaintext, err := bob.Decrypt(initMsg)
	require.NoError(t, err)
	require.Equal(t, []byte("hello with OTK"), plaintext)

	response, err := bob.Encrypt([]byte("ack"))
	require.NoError(t, err)

	ackText, err := alice.Decrypt(response)
	require.NoError(t, err)
	require.Equal(t, []byte("ack"), ackText)
}

func TestIsInitiator(t *testing.T) {
	alice, bob, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()
	defer bob.Delete()

	require.True(t, alice.IsInitiator())
	require.False(t, bob.IsInitiator())

	_, err := bob.Decrypt(firstMsg)
	require.NoError(t, err)
}

func TestReceiverHasOneTimePublicKey(t *testing.T) {
	alice, bob, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()
	defer bob.Delete()

	require.False(t, bob.ReceiverHasOneTimePublicKey())

	_, err := bob.Decrypt(firstMsg)
	require.NoError(t, err)
}

func TestMultipleMessageExchange(t *testing.T) {
	alice, bob, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()
	defer bob.Delete()

	plaintext, err := bob.Decrypt(firstMsg)
	require.NoError(t, err)
	require.Equal(t, []byte("first"), plaintext)

	messages := []string{"a", "bb", "ccc", "dddd", "eeeee"}
	for _, text := range messages {
		msg, encErr := alice.Encrypt([]byte(text))
		require.NoError(t, encErr)

		got, decErr := bob.Decrypt(msg)
		require.NoError(t, decErr)
		require.Equal(t, []byte(text), got)

		resp, encErr := bob.Encrypt([]byte(strings.ToUpper(text)))
		require.NoError(t, encErr)

		gotResp, decErr := alice.Decrypt(resp)
		require.NoError(t, decErr)
		require.Equal(t, []byte(strings.ToUpper(text)), gotResp)
	}
}

func TestSerializeDeserializeSession(t *testing.T) {
	alice, bob, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()
	defer bob.Delete()

	_, err := bob.Decrypt(firstMsg)
	require.NoError(t, err)

	// Serialize alice's session.
	data := alice.Serialize()
	require.NotEmpty(t, data)

	// Deserialize into a new session.
	alice2, err := alice.Deserialize(data)
	require.NoError(t, err)
	defer alice2.Delete()
	require.NoError(t, alice2.SetupDefaults())

	// The restored session should still be able to decrypt a message from bob.
	msg, err := bob.Encrypt([]byte("after restore"))
	require.NoError(t, err)

	got, err := alice2.Decrypt(msg)
	require.NoError(t, err)
	require.Equal(t, []byte("after restore"), got)
}

func TestEncrypt_PlaintextTooLong(t *testing.T) {
	alice, _, _ := setupSessionPairNoOTK(t)
	defer alice.Delete()

	// MAX_PLAIN_TEXT_LEN = 30000
	tooLong := make([]byte, RatchetCommonMaxPlainTextLen+1)
	_, err := alice.Encrypt(tooLong)
	require.Error(t, err)
}

func TestDecrypt_MessageAlreadyDecrypted(t *testing.T) {
	alice, bob, firstMsg := setupSessionPairNoOTK(t)
	defer alice.Delete()
	defer bob.Delete()

	_, err := bob.Decrypt(firstMsg)
	require.NoError(t, err)

	_, err = bob.Decrypt(firstMsg)
	require.Error(t, err)
}
