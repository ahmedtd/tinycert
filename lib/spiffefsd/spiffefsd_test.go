package spiffefsd

import (
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTrustDomain(t *testing.T) {
	valid := []string{
		"cluster.local",
		"example.org",
		"a",
		"my-org_1.example",
		"1.2.3.4",
	}
	for _, td := range valid {
		if err := ValidateTrustDomain(td); err != nil {
			t.Errorf("ValidateTrustDomain(%q) = %v, want nil", td, err)
		}
	}

	invalid := []string{
		"",
		".",
		"..",
		"../etc",
		"../../tmp/evil",
		"foo/bar",
		`foo\bar`,
		"/abs",
		"Example.org",
		"example.org:8080",
		"exa mple.org",
		"example.org\x00",
		"[::1]",
		"ex%2fample",
		"éxample.org",
	}
	for _, td := range invalid {
		if err := ValidateTrustDomain(td); err == nil {
			t.Errorf("ValidateTrustDomain(%q) = nil, want error", td)
		}
	}
}

func TestTrustBundleFileName(t *testing.T) {
	got, err := TrustBundleFileName("cluster.local")
	if err != nil {
		t.Fatalf("TrustBundleFileName: %v", err)
	}
	if want := "cluster.local.spiffe-trust-bundle.x509.pem"; got != want {
		t.Errorf("TrustBundleFileName = %q, want %q", got, want)
	}

	if _, err := TrustBundleFileName("../evil"); err == nil {
		t.Errorf("TrustBundleFileName(%q) succeeded, want error", "../evil")
	}
}

func TestTrustDomainFromSPIFFEID(t *testing.T) {
	testCases := []struct {
		uri     string
		want    string
		wantErr bool
	}{
		{uri: "spiffe://cluster.local/ns/default/sa/default", want: "cluster.local"},
		{uri: "spiffe://cluster.local", want: "cluster.local"},
		{uri: "https://cluster.local/ns/default/sa/default", wantErr: true},
		{uri: "spiffe://user@cluster.local/ns/default", wantErr: true},
		{uri: "spiffe://cluster.local:443/ns/default", wantErr: true},
		{uri: "spiffe://Cluster.Local/ns/default", wantErr: true},
		{uri: "spiffe:///ns/default", wantErr: true},
		{uri: "spiffe:cluster.local", wantErr: true},
		{uri: "spiffe://%2e%2e%2f%2e%2e%2fevil/ns/default", wantErr: true},
	}
	for _, tc := range testCases {
		u, err := url.Parse(tc.uri)
		if err != nil {
			// Unparseable URIs can never make it into a parsed certificate's
			// URIs field, so there is nothing further to check.
			continue
		}
		got, err := trustDomainFromSPIFFEID(u)
		if tc.wantErr {
			if err == nil {
				t.Errorf("trustDomainFromSPIFFEID(%q) = %q, want error", tc.uri, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("trustDomainFromSPIFFEID(%q) = %v, want nil", tc.uri, err)
			continue
		}
		if got != tc.want {
			t.Errorf("trustDomainFromSPIFFEID(%q) = %q, want %q", tc.uri, got, tc.want)
		}
	}
}

// TestAuthenticatePeerRejectsPathEscape checks that a peer can't make
// AuthenticatePeer read a trust bundle from outside the credential folder by
// presenting a certificate with a crafted trust domain.
func TestAuthenticatePeerRejectsPathEscape(t *testing.T) {
	root := t.TempDir()
	credFolder := filepath.Join(root, "creds")
	if err := os.Mkdir(credFolder, 0o755); err != nil {
		t.Fatal(err)
	}

	// Plant a file that a successful escape would reach.  Its contents don't
	// matter; the point is that the error must come from trust domain
	// validation, not from a failed read or failed chain verification.
	if err := os.WriteFile(filepath.Join(root, "evil"+TrustBundleFileSuffix), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := NewCredentialFolder(credFolder)
	if err != nil {
		t.Fatal(err)
	}

	// Build the URI by hand, since this is what a hostile certificate could
	// carry in its SAN after x509 parsing.
	leaf := &x509.Certificate{
		URIs: []*url.URL{{Scheme: "spiffe", Host: "../evil", Path: "/ns/default/sa/default"}},
	}

	_, err = f.AuthenticatePeer([]*x509.Certificate{leaf})
	if err == nil {
		t.Fatal("AuthenticatePeer succeeded, want error")
	}
	if !strings.Contains(err.Error(), "invalid trust domain") {
		t.Errorf("AuthenticatePeer error = %v, want trust domain validation error", err)
	}
}
