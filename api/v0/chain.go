package v0

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// DigestPrefix is how every digest in the contract starts.
const DigestPrefix = "sha-256:"

// Digest returns the contract's digest of data: SHA-256, base64url without
// padding, with its algorithm prefix.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return DigestPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// ChainHash computes a decision record's hash: the digest of the record in
// canonical JSON (RFC 8785), with its chain filled in but without chain.hash
// itself. Record N's hash therefore covers record N-1's hash through
// chain.prev, which is what makes the journal a chain, and anyone with the
// records and an RFC 8785 implementation can recompute it, in any language.
func ChainHash(d Decision) (string, error) {
	if d.Chain == nil {
		return "", fmt.Errorf("chain is not set")
	}
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", err
	}
	delete(doc["chain"].(map[string]any), "hash")
	canon, err := Canonical(doc)
	if err != nil {
		return "", err
	}
	return Digest(canon), nil
}

// Link fills d.Chain so that d follows prev, and sets its hash. prev is nil
// for the first record.
func Link(d Decision, prev *Decision) (Decision, error) {
	chain := ChainLink{}
	if prev != nil {
		if prev.Chain == nil {
			return d, fmt.Errorf("previous record has no chain")
		}
		chain.Seq = prev.Chain.Seq + 1
		chain.Prev = prev.Chain.Hash
	}
	d.Chain = &chain
	hash, err := ChainHash(d)
	if err != nil {
		return d, err
	}
	d.Chain.Hash = hash
	return d, nil
}

// Verify checks that each record's hash is right and that each follows the
// one before it. It returns the index of the first bad record, or -1.
func Verify(records []Decision) (int, error) {
	for i, d := range records {
		if d.Chain == nil {
			return i, fmt.Errorf("record %d has no chain", i)
		}
		want, err := ChainHash(d)
		if err != nil {
			return i, err
		}
		if d.Chain.Hash != want {
			return i, fmt.Errorf("record %d (seq %d, %s): hash does not match its contents", i, d.Chain.Seq, d.ID)
		}
		if i == 0 {
			continue
		}
		p := records[i-1].Chain
		if d.Chain.Seq != p.Seq+1 || d.Chain.Prev != p.Hash {
			return i, fmt.Errorf("record %d (seq %d, %s): does not follow seq %d", i, d.Chain.Seq, d.ID, p.Seq)
		}
	}
	return -1, nil
}
