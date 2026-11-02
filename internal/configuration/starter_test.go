package configuration_test

import (
	"encoding/json"
	"reflect"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/testhelpers"
	"github.com/vladmsnk/doorward/schema"
)

func TestStarterMandate(t *testing.T) {
	man := testhelpers.Example[v0.Manifest](t, "config/manifest-ledger-mcp.yaml")
	md, writes, err := configuration.StarterMandate("ledger-starter", man)
	if err != nil {
		t.Fatal(err)
	}
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(md)
	if err := v.Check(schema.Mandate, doc); err != nil {
		t.Fatalf("the starter mandate is not valid: %v", err)
	}
	aud := []string{man.Spec.Audience}
	want := []v0.Permission{{Locations: aud, Actions: []string{"list_unmatched"}}, {Locations: aud, Actions: []string{"write_off"}}}
	if !reflect.DeepEqual(md.Spec.Permissions, want) || !reflect.DeepEqual(writes, []string{"post_entry"}) {
		t.Errorf("permissions %+v, writes left out %v", md.Spec.Permissions, writes)
	}
	if md.Spec.Principal != v0.PrincipalUser || md.Spec.Consent == nil || md.Spec.Approval == nil || md.Spec.Approval.Required != 1 {
		t.Errorf("spec: %+v", md.Spec)
	}

	// Without a critical operation, nobody needs to approve anything.
	man.Spec.Operations = man.Spec.Operations[:2]
	if md, _, err = configuration.StarterMandate("s", man); err != nil || md.Spec.Approval != nil || len(md.Spec.Permissions) != 1 {
		t.Errorf("reads only: %+v, %v", md.Spec, err)
	}
	man.Spec.Operations = man.Spec.Operations[1:2]
	if _, writes, err = configuration.StarterMandate("s", man); err == nil || len(writes) != 1 {
		t.Errorf("writes only: %v, %v", writes, err)
	}
}
