// Package spiffefsd provides utilities for loading a SPIFFE Filesystem Delivery
// credential folder, and using it for TLS client and server configs.
package spiffefsd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

type CredentialFolder struct {
	Path string

	// StaticServerAuthorization is used by the client.  It provides a mapping
	// between DNS names that the client will try to connect to, and the SPIFFE
	StaticServerAuthorization map[string]string
}

func NewCredentialFolder(path string) (*CredentialFolder, error) {
	return &CredentialFolder{
		Path: path,
	}, nil
}

func (f *CredentialFolder) PrepareClientTLSConfig(cfg *tls.Config) {
	cfg.GetClientCertificate = f.GetClientCertificate

	// Disable normal verification of the server certificate, which will not
	// work when the server presents a SPIFFE certificate, and supply our own
	// verification function.
	cfg.InsecureSkipVerify = true
	// cfg.VerifyPeerCertificate = f.ClientVerifyPeerCertificate
	cfg.VerifyConnection = f.ClientVerifyPeerConnection
}

func (f *CredentialFolder) PrepareServerTLSConfig(cfg *tls.Config) {
	cfg.GetCertificate = f.GetCertificate

	// Tell the client to send client certs if they have any.  Don't
	// pass in roots to verify the client certificate, since we expect
	// multiple types signed by different CAs.  Instead, each endpoint
	// will do the appropriate client certificate verification.
	cfg.ClientAuth = tls.RequestClientCert
}

func (f *CredentialFolder) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return f.GetCertificate(nil)
}

func (f *CredentialFolder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	credentialBundleBytes, err := os.ReadFile(filepath.Join(f.Path, "credential-bundle.private-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("while reading credential-bundle.private-key.pem: %w", err)
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

// func (f *CredentialFolder) ClientVerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
// 	peerCertificates := []*x509.Certificate{}
// 	for _, rawCert := range rawCerts {
// 		cert, err := x509.ParseCertificate(rawCert)
// 		if err != nil {
// 			return fmt.Errorf("while parsing certificate: %w", err)
// 		}

// 		peerCertificates = append(peerCertificates, cert)
// 	}

// 	peerInfo, err := f.AuthenticatePeer(peerCertificates)
// 	if err != nil {
// 		return fmt.Errorf("while authenticating peer: %w", err)
// 	}
// 	if peerInfo == nil {

// 	}

// }

func (f *CredentialFolder) ClientVerifyPeerConnection(connState tls.ConnectionState) error {
	if len(connState.PeerCertificates) == 0 {
		return fmt.Errorf("server did not present certificates")
	}

	peerInfo, err := f.AuthenticatePeer(connState.PeerCertificates)
	if err != nil {
		return fmt.Errorf("while authenticating peer: %w", err)
	}
	if peerInfo == nil {
		return fmt.Errorf("server did not provide valid SPIFFE certificate from known trust domain")
	}

	if f.StaticServerAuthorization[connState.ServerName] != peerInfo.SPIFFEURI.String() {
		return fmt.Errorf("server authorization failure: %q is not allowed to serve %q", peerInfo.SPIFFEURI.String(), connState.ServerName)
	}

	return nil
}

type PeerInfo struct {
	SPIFFEURI               *url.URL
	VerifiedLeafCertificate *x509.Certificate
}

func (f *CredentialFolder) AuthenticatePeer(peerCertificates []*x509.Certificate) (*PeerInfo, error) {
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

	// Build root pool for the peer's trust domain.

	// TODO: Defend against path escapes in the peer's trust domain.
	peerTrustDomain := leafCert.URIs[0].Host
	peerTrustBundleFile := peerTrustDomain + ".spiffe-trust-bundle.pem"
	peerTrustBundleBytes, err := os.ReadFile(filepath.Join(f.Path, peerTrustBundleFile))
	if err != nil {
		return nil, fmt.Errorf("while reading trust bundle for %q: %w", peerTrustDomain, err)
	}
	peerRootPool := x509.NewCertPool()
	peerRootPool.AppendCertsFromPEM(peerTrustBundleBytes)

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
