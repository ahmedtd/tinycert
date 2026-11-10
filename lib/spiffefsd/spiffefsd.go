// Package spiffefsd provides utilities for loading a SPIFFE Filesystem Delivery
// credential folder, and using it for TLS client and server configs.
package spiffefsd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// SPIFFECredentialBundleFileName is the name of the credential bundle file within
	// a credential folder, as defined in section 2 of the SPIFFE Filesystem
	// Delivery standard.
	SPIFFECredentialBundleFileName = "credential-bundle.private-key.x509.pem"

	// SPIFFETrustBundleFileSuffix is appended to a trust domain name to form the name
	// of that trust domain's trust bundle file within a credential folder, as
	// defined in section 2.2 of the SPIFFE Filesystem Delivery standard.
	SPIFFETrustBundleFileSuffix = ".spiffe-trust-bundle.x509.pem"

	// ServiceCredentialBundleFileName is the name of the of the credential
	// bundle that contains the Service DNS certificate and private key.  This
	// is a tinycert-specific extension to the SPIFFE Filesystem Delivery
	// standard.
	ServiceCredentialBundleFileName = "service-credential-bundle.private-key.x509.pem"

	// ServiceTrustBundleFileName is the name of the trust bundle that contains
	// the trust anchors for verifying Service DNS certificates.  This is a
	// tinycert-specific extension to the SPIFFE Filesystem Delivery standard.
	ServiceTrustBundleFileName = "service-trust-bundle.x509.pem"
)

// validateTrustDOmain checks that td is a syntactically valid SPIFFE trust
// domain name, per section 2.1 of the SPIFFE-ID standard: a non-empty string
// made up only of lowercase letters, digits, dots, dashes, and underscores.
//
// Among other things, this guarantees that td contains no path separators, so
// it is safe to use as a component of a filename.
func validateTrustDOmain(td string) error {
	if td == "" {
		return fmt.Errorf("trust domain is empty")
	}
	// Not strictly forbidden by the SPIFFE-ID standard's character set, but
	// these are never legitimate trust domains, and rejecting them keeps the
	// resulting filenames unambiguous.
	if td == "." || td == ".." {
		return fmt.Errorf("trust domain %q is not valid", td)
	}
	for i := 0; i < len(td); i++ {
		c := td[i]
		switch {
		case 'a' <= c && c <= 'z':
		case '0' <= c && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return fmt.Errorf("trust domain %q contains invalid character %q at offset %d", td, c, i)
		}
	}
	return nil
}

// trustDomainFromSPIFFEID extracts and validates the trust domain from a SPIFFE
// ID URI.
func trustDomainFromSPIFFEID(id *url.URL) (string, error) {
	if id.Scheme != "spiffe" {
		return "", fmt.Errorf("URI %q does not have scheme \"spiffe\"", id.String())
	}
	if id.User != nil {
		return "", fmt.Errorf("SPIFFE ID %q must not contain userinfo", id.String())
	}
	if id.Opaque != "" {
		return "", fmt.Errorf("SPIFFE ID %q is not a valid hierarchical URI", id.String())
	}
	// Host (rather than Hostname) so that a port, which SPIFFE IDs may not
	// contain, is caught as an invalid character.
	if err := validateTrustDOmain(id.Host); err != nil {
		return "", fmt.Errorf("SPIFFE ID %q has invalid trust domain: %w", id.String(), err)
	}
	return id.Host, nil
}

// CredentialFolder knows how to read an extended version of the folder layout
// specified in the SPIFFE Filesystem Delivery specification.
//
// CredentialFolder can use both SPIFFE certs (issued by
// ahmedtd.github.com/tinycert-spiffe) as well as Service DNS certificates
// (issued by ahmedtd.github.com/tinycert-service).
//
// File layout:
//   - credential-bundle.private-key.x509.pem: The SPIFFE private key and certificate chain.
//   - ${x}.spiffe-trust-bundle.x509.pem: The root certificates for SPIFFE trust domain X.
//   - service-credential-bundle.private-key.x509.pem: The private key and certificate chain issued by ahmedtd.github.com/tinycert-service.
//   - service-trust-bundle.x509.pem: The root certificates for the service DNS certificates issued by ahmedtd.github.com/tinycert-service.
type CredentialFolder struct {
	Path string

	// StaticServerAuthorization is used by the client.  It provides a mapping
	// between DNS names that the client will try to connect to, and the SPIFFE
	StaticServerAuthorization map[string]string

	// lock covers loadedState
	lock        sync.Mutex
	loadedState *loadedState
}

func NewCredentialFolder(path string) (*CredentialFolder, error) {
	return &CredentialFolder{
		Path: path,
	}, nil
}

// ClientTLSConfig returns a tls.Config to use for creating clients.
//
// Only the SPIFFE certificate can be used as the client certificate.
//
// Server certificate verification uses the following logic:
//   - If the server provides a certificate that looks like a Service DNS
//     certificate (DNS SAN of the form foo.bar.svc), then it is verified
//     using the Service DNS roots from the folder.
//   - If the server provides a certificate that looks like a SPIFFE certificate,
//     then it is verified against the appropriate SPIFE trust bundle from the
//     folder.  The resulting SPIFFE ID is then checked against
//     StaticServerAuthorization, to confirm that the SPIFFE ID is trusted for
//     the domain name we tried to connect to.
func (f *CredentialFolder) ClientTLSConfig() *tls.Config {
	cfg := &tls.Config{
		GetClientCertificate: f.GetClientCertificate,
		VerifyConnection:     f.ClientVerifyPeerConnection,

		// We need to disable built-in verification because it doesn't support
		// SPIFFE certificates, and doesn't support reloading the roots from the
		// filesystem.
		InsecureSkipVerify: true,
	}

	return cfg
}

// ServerTLSConfig returns a tls.Config to use for running servers.  It will
// prefer Service DNS certificates if they are available, otherwise it will fall
// back to serving with the SPIFFE certificate.
//
// The serving certificate is automatically reloaded from the filesystem
// periodically in order to seamlessly handle credential rotations.
//
// Clients are requested to present a certificate, but are not required to.  No
// verification of the client's certificate is done during TLS connection
// establishment.  Instead you should use AuthenticatePeer to check the client
// certificates on a per-request basis.  This allows better error messaging for
// clients, as well as mixing authenticated and unauthenticated endpoints in
// your server.
func (f *CredentialFolder) ServerTLSConfig() *tls.Config {
	cfg := &tls.Config{
		GetCertificate: f.GetServerCertificate,

		// Tell the client to send client certs if they have any.  Don't pass in
		// roots to verify the client certificate, since we expect multiple
		// types signed by different CAs.
		//
		// Instead each endpoint or handler should use AuthenticatePeer() to
		// check the certificate chain provided by the client on each request.
		// This allows better error messaging to the client, since they can get
		// a rich error response rather than just a TLS connection failure.
		//
		// TODO: Add caching in AuthenticatePeer().
		ClientAuth: tls.RequestClientCert,
	}

	return cfg
}

func (f *CredentialFolder) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	loadedState, err := f.readState()
	if err != nil {
		return nil, fmt.Errorf("while loading state: %w", err)
	}
	if loadedState.spiffeCreds != nil {
		return loadedState.spiffeCreds, nil
	}
	return nil, fmt.Errorf("SPIFFE creds not available")
}

func (f *CredentialFolder) GetServerCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	loadedState, err := f.readState()
	if err != nil {
		return nil, fmt.Errorf("while loading state: %w", err)
	}

	if loadedState.serviceCreds != nil {
		return loadedState.serviceCreds, nil
	}
	if loadedState.spiffeCreds != nil {
		return loadedState.spiffeCreds, nil
	}
	return nil, fmt.Errorf("neither Service DNS nor SPIFFE creds available")
}

func (f *CredentialFolder) ClientVerifyPeerConnection(connState tls.ConnectionState) error {
	if len(connState.PeerCertificates) == 0 {
		return fmt.Errorf("server did not present certificates")
	}

	switch {
	case looksLikeServiceDNSCertificate(connState.PeerCertificates[0]):
		if err := f.authenticateServiceDNSPeer(connState.PeerCertificates, connState.ServerName); err != nil {
			return fmt.Errorf("while verifying Service DNS certificate: %w", err)
		}
	case looksLikeSPIFFECertificate(connState.PeerCertificates[0]):
		peerInfo, err := f.AuthenticateSPIFFEPeer(connState.PeerCertificates)
		if err != nil {
			return fmt.Errorf("while verifying SPIFFE certificate: %w", err)
		}
		if peerInfo == nil {
			return fmt.Errorf("server did not provide valid SPIFFE certificate from known trust domain")
		}
		if f.StaticServerAuthorization[connState.ServerName] != peerInfo.SPIFFEURI.String() {
			return fmt.Errorf("server authorization failure: %q is not allowed to serve %q", peerInfo.SPIFFEURI.String(), connState.ServerName)
		}

	default:
		return fmt.Errorf("unrecognized certificate")
	}

	return nil
}

func looksLikeServiceDNSCertificate(cert *x509.Certificate) bool {
	for _, san := range cert.DNSNames {
		if strings.HasSuffix(san, ".svc") {
			return true
		}
	}
	return false
}

func looksLikeSPIFFECertificate(cert *x509.Certificate) bool {
	for _, san := range cert.URIs {
		if san.Scheme == "spiffe" {
			return true
		}
	}
	return false
}

func (f *CredentialFolder) authenticateServiceDNSPeer(peerCertificates []*x509.Certificate, connectingTo string) error {
	leafCert := peerCertificates[0]

	// Build intermediate pool from other certs server sent.
	peerIntermediatePool := x509.NewCertPool()
	if len(peerCertificates) > 1 {
		for _, intermediate := range peerCertificates[1:] {
			peerIntermediatePool.AddCert(intermediate)
		}
	}

	loadedState, err := f.readState()
	if err != nil {
		return fmt.Errorf("while loading state: %w", err)
	}

	chains, err := leafCert.Verify(x509.VerifyOptions{
		Intermediates: peerIntermediatePool,
		Roots:         loadedState.serviceTrustBundle,
		DNSName:       connectingTo,
	})
	if err != nil {
		return fmt.Errorf("while verifying peer certificate: %w", err)
	}
	if len(chains) == 0 {
		return fmt.Errorf("peer certificate did not chain to any trusted Service DNS roots")
	}

	return nil
}

type PeerInfo struct {
	SPIFFEURI               *url.URL
	VerifiedLeafCertificate *x509.Certificate
}

func (f *CredentialFolder) AuthenticateSPIFFEPeer(peerCertificates []*x509.Certificate) (*PeerInfo, error) {
	// Caution! Do not read any properties of the leaf certificate except for
	// the SPIFFE trust domain above the call to leafCert.Verify.

	// Did client actually send any certificates?  Not necessarily an error.
	if len(peerCertificates) == 0 {
		return nil, nil
	}

	leafCert := peerCertificates[0]
	if len(leafCert.URIs) != 1 {
		return nil, fmt.Errorf("peer's certificate is not valid SPIFFE")
	}

	// Build intermediate pool from other certs client sent.
	peerIntermediatePool := x509.NewCertPool()
	if len(peerCertificates) > 1 {
		for _, intermediate := range peerCertificates[1:] {
			peerIntermediatePool.AddCert(intermediate)
		}
	}

	loadedState, err := f.readState()
	if err != nil {
		return nil, fmt.Errorf("while loading state: %w", err)
	}

	// Build root pool for the peer's trust domain.

	// The peer's trust domain is attacker-controlled at this point (the
	// certificate has not been verified yet), and is used to build a path, so
	// it must be validated before use.
	peerTrustDomain, err := trustDomainFromSPIFFEID(leafCert.URIs[0])
	if err != nil {
		return nil, fmt.Errorf("peer's certificate is not valid SPIFFE: %w", err)
	}
	peerRootPool, ok := loadedState.spiffeTrustBundles[peerTrustDomain]
	if !ok {
		return nil, fmt.Errorf("no trust bundle available for peer trust domain %q", peerTrustDomain)
	}

	chains, err := leafCert.Verify(x509.VerifyOptions{
		Intermediates: peerIntermediatePool,
		Roots:         peerRootPool,
	})
	if err != nil {
		return nil, fmt.Errorf("while verifying peer certificate: %w", err)
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("peer certificate did not chain to any trusted roots for %q", peerTrustDomain)
	}

	return &PeerInfo{
		SPIFFEURI:               leafCert.URIs[0],
		VerifiedLeafCertificate: leafCert,
	}, nil
}

func (f *CredentialFolder) readState() (*loadedState, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.loadedState != nil && time.Now().Before(f.loadedState.nextRefreshAt) {
		return f.loadedState, nil
	}

	spiffeCreds, err := loadCredsFromBundle(filepath.Join(f.Path, SPIFFECredentialBundleFileName))
	if errors.Is(err, os.ErrNotExist) {
		// OK, no SPIFFE creds are mounted.
	} else if err != nil {
		return nil, fmt.Errorf("while loading SPIFFE credentials: %w", err)
	}

	spiffeTrustBundles, err := loadAllSPIFFETrustBundles(f.Path)
	if err != nil {
		return nil, fmt.Errorf("while loading all SPIFFE trust bundles: %w", err)
	}

	serviceCreds, err := loadCredsFromBundle(filepath.Join(f.Path, ServiceCredentialBundleFileName))
	if errors.Is(err, os.ErrNotExist) {
		// OK, no service DNS creds are mounted.
	} else if err != nil {
		return nil, fmt.Errorf("while loading Service DNS credentials: %w", err)
	}

	serviceTrustBundle, err := loadTrustBundle(filepath.Join(f.Path, ServiceTrustBundleFileName))

	f.loadedState = &loadedState{
		nextRefreshAt: time.Now().Add(5 * time.Minute),

		spiffeCreds:        spiffeCreds,
		spiffeTrustBundles: spiffeTrustBundles,

		serviceCreds:       serviceCreds,
		serviceTrustBundle: serviceTrustBundle,
	}

	return f.loadedState, nil
}

type loadedState struct {
	nextRefreshAt time.Time

	spiffeCreds        *tls.Certificate
	spiffeTrustBundles map[string]*x509.CertPool

	serviceCreds       *tls.Certificate
	serviceTrustBundle *x509.CertPool
}

func loadCredsFromBundle(path string) (*tls.Certificate, error) {
	credentialBundleBytes, err := os.ReadFile(filepath.Join(path))
	if err != nil {
		return nil, fmt.Errorf("while reading %s: %w", path, err)
	}

	cert := &tls.Certificate{}

	var block *pem.Block
	rest := credentialBundleBytes
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch block.Type {
		case "PRIVATE KEY":
			cert.PrivateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("while parsing private key from credential bundle: %w", err)
			}
		case "CERTIFICATE":
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}

	if cert.PrivateKey == nil {
		return nil, fmt.Errorf("client credential bundle had no private key")
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("client credential bundle had no certificates")
	}

	return cert, nil
}

func loadAllSPIFFETrustBundles(folderPath string) (map[string]*x509.CertPool, error) {
	var trustBundleFiles []string
	err := filepath.WalkDir(folderPath, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, SPIFFETrustBundleFileSuffix) {
			trustBundleFiles = append(trustBundleFiles, path)
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("while listing SPIFFE trust bundles: %w", err)
	}

	trustBundles := map[string]*x509.CertPool{}
	for _, trustBundleFile := range trustBundleFiles {
		trustDomain := strings.TrimSuffix(filepath.Base(trustBundleFile), SPIFFETrustBundleFileSuffix)

		bundle, err := loadTrustBundle(trustBundleFile)
		if errors.Is(err, os.ErrNotExist) {
			// OK: file disappeared after listing but before reading.
		} else if err != nil {
			return nil, fmt.Errorf("while reading file: %w", err)
		}

		trustBundles[trustDomain] = bundle
	}

	return trustBundles, nil
}

func loadTrustBundle(path string) (*x509.CertPool, error) {
	trustBundleBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("while reading file: %w", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(trustBundleBytes)
	return certPool, nil
}
