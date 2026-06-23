package environments

import (
	"path/filepath"
	"testing"
)

func TestPackageReferences(t *testing.T) {
	env := TLSEnvironment{Hostname: "host", UUID: "uuid", Secret: "secret"}

	if got := PackageDownloadURL(env, "osquery.deb"); got != "https://host/uuid/secret/package/osquery.deb" {
		t.Fatalf("local package URL = %q", got)
	}
	if got := PackageDownloadURL(env, "https://example.com/osquery.deb"); got != "https://example.com/osquery.deb" {
		t.Fatalf("HTTPS package URL = %q", got)
	}
	if got := PackageDownloadURL(env, "../secret"); got != "" {
		t.Fatalf("traversal package URL = %q", got)
	}

	got, err := PackageFilePath("packages", "prod", "osquery.deb")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("packages", "prod", "osquery.deb"); got != want {
		t.Fatalf("package path = %q, want %q", got, want)
	}

	for _, pkg := range []string{"../secret", "dir/osquery.deb", `dir\osquery.deb`, "/tmp/osquery.deb", ".", ".."} {
		if _, err := PackageFilePath("packages", "prod", pkg); err == nil {
			t.Fatalf("PackageFilePath accepted %q", pkg)
		}
	}
}
