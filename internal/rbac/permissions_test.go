package rbac

import (
	"regexp"
	"testing"
)

var permissionFormat = regexp.MustCompile(`^[a-z]+:[a-z_]+$`)

func TestAllPermissions_FollowFormat(t *testing.T) {
	for _, p := range All() {
		if !permissionFormat.MatchString(p) {
			t.Errorf("permission %q does not match format resource:verb", p)
		}
	}
}

func TestAllPermissions_NoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range All() {
		if seen[p] {
			t.Errorf("duplicate permission %q", p)
		}
		seen[p] = true
	}
}
