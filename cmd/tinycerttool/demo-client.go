package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/ahmedtd/tinycert/lib/spiffefsd"
	"github.com/google/subcommands"
)

type DemoClientCommand struct {
	fetchURL string

	spiffeCredentialFolder string
	serverSPIFFEID         string
}

var _ subcommands.Command = (*DemoClientCommand)(nil)

func (*DemoClientCommand) Name() string {
	return "https-client"
}

func (*DemoClientCommand) Synopsis() string {
	return "Run a vanilla HTTPS client"
}

func (*DemoClientCommand) Usage() string {
	return ``
}

func (c *DemoClientCommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.fetchURL, "fetch-url", "", "URL to poll")
	f.StringVar(&c.spiffeCredentialFolder, "spiffe-credential-folder", "", "SPIFFE Filesystem Delivery credential folder")
	f.StringVar(&c.serverSPIFFEID, "server-spiffe-id", "", "What verified SPIFFE ID should the server present?")
}

func (c *DemoClientCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		slog.ErrorContext(ctx, "Error: ", slog.String("err", err.Error()))
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *DemoClientCommand) do(ctx context.Context) error {
	spiffeCredProvider, err := spiffefsd.NewCredentialFolder(c.spiffeCredentialFolder)
	if err != nil {
		return fmt.Errorf("while loading SPIFFE credential folder: %w", err)
	}

	// Set up the server authorization map
	fetchURLParsed, err := url.Parse(c.fetchURL)
	if err != nil {
		return fmt.Errorf("while parsing fetch URL: %w", err)
	}
	spiffeCredProvider.StaticServerAuthorization = map[string]string{}
	spiffeCredProvider.StaticServerAuthorization[fetchURLParsed.Host] = c.serverSPIFFEID

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: spiffeCredProvider.ClientTLSConfig(),
		},
	}

	for range time.Tick(10 * time.Second) {
		if err := c.pollOnce(ctx, client); err != nil {
			slog.ErrorContext(ctx, "Error: ", slog.String("err", err.Error()))
		}
	}

	return nil
}

func (c *DemoClientCommand) pollOnce(ctx context.Context, client *http.Client) error {
	resp, err := client.Get(c.fetchURL)
	if err != nil {
		return fmt.Errorf("while getting URL: %w", err)

	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("while reading body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx status %d %q %q", resp.StatusCode, resp.Status, string(body))
	}

	slog.InfoContext(ctx, "Got response body", slog.String("body", string(body)))
	return nil
}
