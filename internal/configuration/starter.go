package configuration

import (
	"fmt"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// StarterMandate is a mandate to begin from for a manifest's operations,
// one where reads pass and critical calls ask: an agent acting for a user
// may run every read operation, and every critical one once the user has
// approved that exact call. Write operations would run on a standing grant
// without asking, so they are left out and returned for the caller to
// point out; a mandate can make a write ask first once approval thresholds
// exist (C10).
func StarterMandate(name string, m v0.Manifest) (v0.Mandate, []string, error) {
	var reads, writes, criticals []string
	for _, op := range m.Spec.Operations {
		switch op.Sensitivity {
		case v0.SensitivityRead:
			reads = append(reads, op.Name)
		case v0.SensitivityWrite:
			writes = append(writes, op.Name)
		case v0.SensitivityCritical:
			criticals = append(criticals, op.Name)
		}
	}
	if len(reads)+len(criticals) == 0 {
		return v0.Mandate{}, writes, fmt.Errorf("manifest %s has no read or critical operations, so a starter mandate would grant nothing", m.Metadata.Name)
	}
	spec := v0.MandateSpec{
		Principal: v0.PrincipalUser,
		Consent: &v0.ConsentTerms{
			Text:        fmt.Sprintf("Use %s for you, to read, and to do what is critical once you approve each exact call.", m.Metadata.Name),
			MaxDuration: v0.Duration(30 * 24 * time.Hour),
		},
		TTL: v0.Duration(15 * time.Minute),
	}
	if len(reads) > 0 {
		spec.Permissions = append(spec.Permissions, v0.Permission{Locations: []string{m.Spec.Audience}, Actions: reads})
	}
	if len(criticals) > 0 {
		spec.Permissions = append(spec.Permissions, v0.Permission{Locations: []string{m.Spec.Audience}, Actions: criticals})
		spec.Approval = &v0.ApprovalPolicy{
			Required:     1,
			Approvers:    v0.Approvers{Kind: v0.ApproverUser},
			MaxAuthAge:   v0.Duration(5 * time.Minute),
			ExpiresAfter: v0.Duration(30 * time.Minute),
		}
	}
	return v0.Mandate{
		TypeMeta: v0.TypeMeta{APIVersion: v0.APIVersion, Kind: v0.KindMandate},
		Metadata: v0.ObjectMeta{
			Name:        name,
			Description: fmt.Sprintf("A starter mandate for manifest %s. Reads run, and each critical call waits for the user's approval.", m.Metadata.Name),
		},
		Spec: spec,
	}, writes, nil
}
