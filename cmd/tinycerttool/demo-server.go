package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/ahmedtd/tinycert/lib/spiffefsd"
	"github.com/google/subcommands"
	"k8s.io/klog/v2"
)

type DemoServerCommand struct {
	listen string

	spiffeCredentialFolder   string
	spiffeCredentialProvider *spiffefsd.CredentialFolder
}

var _ subcommands.Command = (*DemoServerCommand)(nil)

func (*DemoServerCommand) Name() string {
	return "demo-server"
}

func (*DemoServerCommand) Synopsis() string {
	return "Run an HTTP server that supports standard and mutual TLS"
}

func (*DemoServerCommand) Usage() string {
	return ``
}

func (c *DemoServerCommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.listen, "listen", "", "<address>:<port> to listen on")
	f.StringVar(&c.spiffeCredentialFolder, "spiffe-credential-folder", "", "SPIFFE Filesystem Delivery credential folder")
}

func (c *DemoServerCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		slog.ErrorContext(ctx, "Error: ", slog.String("err", err.Error()))
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *DemoServerCommand) do(ctx context.Context) error {
	spiffeCredProvider, err := spiffefsd.NewCredentialFolder(c.spiffeCredentialFolder)
	if err != nil {
		return fmt.Errorf("while loading SPIFFE credential folder: %w", err)
	}
	c.spiffeCredentialProvider = spiffeCredProvider

	serveMux := http.NewServeMux()
	serveMux.HandleFunc("GET /healthz", c.handleGetHealthz)
	serveMux.HandleFunc("GET /spiffe-echo", c.handleGetSPIFFEEcho)

	tlsConfig := &tls.Config{}
	c.spiffeCredentialProvider.PrepareServerTLSConfig(tlsConfig)

	server := &http.Server{
		Addr: c.listen,

		Handler: serveMux,

		TLSConfig: tlsConfig,

		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("while listening: %w", err)
	}

	return nil
}

func (c *DemoServerCommand) handleGetHealthz(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("Error while writing response: %v", err)
		return
	}
}

func (c *DemoServerCommand) handleGetSPIFFEEcho(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "SPIFFE client certificate authentication required", http.StatusUnauthorized)
		return
	}

	peerInfo, err := c.spiffeCredentialProvider.AuthenticatePeer(r.TLS.PeerCertificates)
	if err != nil {
		slog.ErrorContext(ctx, "Error while authenticating peer SPIFFE credential", slog.Any("err", err))
		http.Error(w, "SPIFFE credential unverifiable", http.StatusUnauthorized)
		return
	}
	if peerInfo == nil {
		slog.ErrorContext(ctx, "No verifiable SPIFFE credential provided")
		http.Error(w, "No verifiable SPIFFE credential provided", http.StatusUnauthorized)
		return
	}

	slog.InfoContext(ctx, "Authenticated peer", slog.Any("peer", peerInfo.SPIFFEURI.String()))

	if _, err := w.Write([]byte("Peer Identity: " + peerInfo.SPIFFEURI.String())); err != nil {
		klog.ErrorS(err, "Error while writing response")
	}
}
