package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ahmedtd/tinycert/lib/localca"
	"github.com/ahmedtd/tinycert/lib/rendezvous"
	"github.com/ahmedtd/tinycert/lib/servicednssigner"
	"github.com/ahmedtd/tinycert/lib/signercontroller"
	"github.com/ahmedtd/tinycert/lib/spiffesigner"
	"github.com/google/subcommands"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/utils/clock"
)

type MeshControllerCommand struct {
	inCluster  bool
	kubeConfig string

	shardingNamespace       string
	shardingPodName         string
	shardingPodUID          string
	shardingApplicationName string

	enableServiceDNSSigner bool
	serviceDNSCAPoolFile   string

	enableSPIFFESigner bool
	spiffeTrustDomain  string
	spiffeCAPoolFile   string

	enablePodIdentitySigner bool
	podIdentityCAPoolFile   string
}

var _ subcommands.Command = (*MeshControllerCommand)(nil)

func (*MeshControllerCommand) Name() string {
	return "controller"
}

func (*MeshControllerCommand) Synopsis() string {
	return "Run the controller"
}

func (*MeshControllerCommand) Usage() string {
	return ``
}

func (c *MeshControllerCommand) SetFlags(f *flag.FlagSet) {
	kubeConfigDefault := ""
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}

	f.StringVar(&c.kubeConfig, "kubeconfig", kubeConfigDefault, "absolute path to the kubeconfig file")
	f.BoolVar(&c.inCluster, "in-cluster", false, "Is the controller running in the cluster it should connect to?")

	f.StringVar(&c.shardingNamespace, "sharding-pod-namespace", "", "(Work Sharding) The namespace the controller is running in")
	f.StringVar(&c.shardingPodName, "sharding-pod-name", "", "(Work Sharding) The pod name of the controller")
	f.StringVar(&c.shardingPodUID, "sharding-pod-uid", "", "(Work Sharding) The pod UID of the controller")
	f.StringVar(&c.shardingApplicationName, "sharding-application-name", "", "(Work Sharding) The application name to disambiguate Leases")

	f.BoolVar(
		&c.enableServiceDNSSigner,
		"enable-service-dns-signer",
		false,
		fmt.Sprintf("Run controller for %s", servicednssigner.Name),
	)
	f.StringVar(
		&c.serviceDNSCAPoolFile,
		"service-dns-ca-pool",
		"",
		"File that contains the CA pool state for "+servicednssigner.Name,
	)

	f.BoolVar(&c.enableSPIFFESigner, "enable-spiffe-signer", false, fmt.Sprintf("Run controller for %s", spiffesigner.Name))
	f.StringVar(&c.spiffeTrustDomain, "spiffe-trust-domain", "", "The SPIFFE trust domain for issued certificates")
	f.StringVar(&c.spiffeCAPoolFile, "spiffe-ca-pool", "", fmt.Sprintf("File that contains the CA pool state for %s", spiffesigner.Name))
}

func (c *MeshControllerCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		slog.ErrorContext(ctx, "Error: ", slog.String("err", err.Error()))
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *MeshControllerCommand) do(ctx context.Context) error {
	var kconfig *rest.Config
	var err error
	if c.inCluster {
		kconfig, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("while creating in-cluster config: %w", err)
		}
	} else {
		// use the current context in kubeconfig
		kconfig, err = clientcmd.BuildConfigFromFlags("", c.kubeConfig)
		if err != nil {
			return fmt.Errorf("while reading kubeconfig: %w", err)
		}
	}

	kc, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return fmt.Errorf("while creating Kubernetes client: %w", err)
	}

	hasher := rendezvous.New(
		kc,
		c.shardingNamespace,
		c.shardingApplicationName,
		c.shardingPodName,
		types.UID(c.shardingPodUID),
		clock.RealClock{},
	)
	go hasher.Run(ctx)

	if c.enableServiceDNSSigner {
		serviceTLSCAPoolBytes, err := os.ReadFile(c.serviceDNSCAPoolFile)
		if err != nil {
			return fmt.Errorf("while reading Service DNS ca pool state: %w", err)
		}

		serviceTLSCAPool, err := localca.Unmarshal(serviceTLSCAPoolBytes)
		if err != nil {
			return fmt.Errorf("while unmarshaling Service DNS ca pool state: %w", err)
		}

		impl := servicednssigner.NewImpl(kc, serviceTLSCAPool)

		controller := signercontroller.New(clock.RealClock{}, impl, kc, hasher)
		go controller.Run(ctx)
	}

	if c.enableSPIFFESigner {
		if c.spiffeTrustDomain == "" {
			return fmt.Errorf("--spiffe-trust-domain must be set")
		}

		poolBytes, err := os.ReadFile(c.spiffeCAPoolFile)
		if err != nil {
			return fmt.Errorf("while reading SPIFFE ca pool state: %w", err)
		}

		caPool, err := localca.Unmarshal(poolBytes)
		if err != nil {
			return fmt.Errorf("while unmarshaling SPIFFE ca pool state: %w", err)
		}

		impl := spiffesigner.NewImpl(c.spiffeTrustDomain, caPool)

		controller := signercontroller.New(clock.RealClock{}, impl, kc, hasher)
		go controller.Run(ctx)
	}

	// TODO: Reload when the file changes.

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	<-signalCh

	return nil
}
