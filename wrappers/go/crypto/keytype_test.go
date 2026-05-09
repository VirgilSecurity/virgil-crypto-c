package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetKeyType(t *testing.T) {
	c := &Crypto{}
	for kt := Rsa2048; kt <= Curve25519MlKem768; kt++ {
		sk, err := c.GenerateKeypairForType(kt)
		require.NoError(t, err)
		require.Equal(t, kt, sk.KeyType())
		require.Equal(t, kt, sk.PublicKey().KeyType())
	}
}
