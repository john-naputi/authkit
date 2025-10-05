// internaltest/fuzz_unit_test.go
package internaltest

import (
	"strings"
	"testing"
)

// keep this in sync with authkit’s impl or export a helper from the package
func isSafeRedirectPathUnderTest(p string) (string, bool) {
	if p == "" {
		return "/", true
	}
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	if strings.HasPrefix(p, "//") || strings.Contains(p, "://") {
		return "", false
	}
	return p, true
}

func FuzzRedirectPath_Pure(f *testing.F) {
	for _, s := range []string{"", "/", "/a", "/a?b=1", "//evil", "http://x", "/%2F..", "/\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, ok := isSafeRedirectPathUnderTest(s)
		if !ok {
			if out != "" {
				t.Fatalf("unsafe returned %q", out)
			}
		} else {
			if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") || strings.Contains(out, "://") {
				t.Fatalf("unsafe marked safe: %q", out)
			}
		}
	})
}
