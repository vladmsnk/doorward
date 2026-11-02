package grant

// VerifierProvider gives the grant verifier.
type VerifierProvider interface {
	GrantVerifier() *Verifier
}
