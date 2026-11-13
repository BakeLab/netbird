package ssh

import cryptossh "golang.org/x/crypto/ssh"

// StrongAlgorithms returns the SSH algorithms enabled by NetBird's built-in
// SSH clients and server. The lists intentionally exclude legacy fallbacks.
func StrongAlgorithms() cryptossh.Algorithms {
	return cryptossh.Algorithms{
		KeyExchanges: []string{
			cryptossh.KeyExchangeMLKEM768X25519,
			cryptossh.KeyExchangeCurve25519,
			cryptossh.KeyExchangeECDHP384,
			cryptossh.KeyExchangeECDHP521,
		},
		Ciphers: []string{
			cryptossh.CipherChaCha20Poly1305,
			cryptossh.CipherAES256GCM,
		},
		MACs: []string{
			cryptossh.HMACSHA512ETM,
			cryptossh.HMACSHA256ETM,
		},
		HostKeys: []string{
			cryptossh.KeyAlgoED25519,
			cryptossh.KeyAlgoRSASHA512,
			cryptossh.KeyAlgoRSASHA256,
		},
		PublicKeyAuths: []string{
			cryptossh.KeyAlgoED25519,
			cryptossh.KeyAlgoRSASHA512,
			cryptossh.KeyAlgoRSASHA256,
			cryptossh.KeyAlgoECDSA521,
			cryptossh.KeyAlgoECDSA384,
		},
	}
}

// ApplyStrongAlgorithms configures a client to fail negotiation if the peer
// does not support the approved algorithm set.
func ApplyStrongAlgorithms(config *cryptossh.ClientConfig) {
	algorithms := StrongAlgorithms()
	config.Config = cryptossh.Config{
		KeyExchanges: algorithms.KeyExchanges,
		Ciphers:      algorithms.Ciphers,
		MACs:         algorithms.MACs,
	}
	config.HostKeyAlgorithms = algorithms.HostKeys
}

// ApplyStrongAlgorithmsToServer configures a server with the same strict
// transport and client public-key authentication policy.
func ApplyStrongAlgorithmsToServer(config *cryptossh.ServerConfig) {
	algorithms := StrongAlgorithms()
	config.Config = cryptossh.Config{
		KeyExchanges: algorithms.KeyExchanges,
		Ciphers:      algorithms.Ciphers,
		MACs:         algorithms.MACs,
	}
	config.PublicKeyAuthAlgorithms = algorithms.PublicKeyAuths
}
