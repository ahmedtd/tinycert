package signercontroller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ahmedtd/tinycert/lib/rendezvous"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	certinformersv1beta1 "k8s.io/client-go/informers/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	certlistersv1beta1 "k8s.io/client-go/listers/certificates/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

type SignerImpl interface {
	SignerName() string
	DesiredClusterTrustBundles() []*certsv1beta1.ClusterTrustBundle
	MakeCert(context.Context, time.Time, time.Time, *certsv1beta1.PodCertificateRequest) ([]*x509.Certificate, error)
}

type Hasher interface {
	AssignedToThisReplica(ctx context.Context, item string) bool
}

// Controller is an in-memory signing controller for PodCertificateRequests.
type Controller struct {
	clock clock.PassiveClock

	kc          kubernetes.Interface
	pcrInformer cache.SharedIndexInformer
	pcrQueue    workqueue.TypedRateLimitingInterface[string]

	hasher Hasher

	handler SignerImpl
}

// New creates a new Controller.
func New(clock clock.PassiveClock, handler SignerImpl, kc kubernetes.Interface, hasher Hasher) *Controller {
	pcrInformer := certinformersv1beta1.NewFilteredPodCertificateRequestInformer(kc, metav1.NamespaceAll, 24*time.Hour, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(opts *metav1.ListOptions) {
		},
	)

	sc := &Controller{
		clock:       clock,
		kc:          kc,
		pcrInformer: pcrInformer,
		pcrQueue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		handler:     handler,
		hasher:      hasher,
	}

	sc.pcrInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
		UpdateFunc: func(old, new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
		DeleteFunc: func(old any) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(old)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
	})

	return sc
}

func (c *Controller) Run(ctx context.Context) {
	defer c.pcrQueue.ShutDown()
	go c.pcrInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.pcrInformer.HasSynced) {
		return
	}

	go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	go wait.JitterUntilWithContext(ctx, c.ensureBundle, 1*time.Minute, 1.0, true)
	<-ctx.Done()
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	key, quit := c.pcrQueue.Get()
	if quit {
		return false
	}
	defer c.pcrQueue.Done(key)

	slog.InfoContext(ctx, "Processing PCR", slog.String("key", key))

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		slog.ErrorContext(ctx, "Error splitting key into namespace and name",
			slog.String("err", err.Error()),
			slog.String("key", key),
		)
		return true
	}

	pcr, err := certlistersv1beta1.NewPodCertificateRequestLister(c.pcrInformer.GetIndexer()).PodCertificateRequests(namespace).Get(name)
	if k8serrors.IsNotFound(err) {
		c.pcrQueue.Forget(key)
		return true
	} else if err != nil {
		slog.ErrorContext(ctx, "Error while retrieving PodCertificateRequest",
			slog.String("err", err.Error()),
			slog.String("key", key),
		)
		return true
	}

	err = c.handlePCR(ctx, pcr)
	if errors.Is(err, rendezvous.ErrNotAssigned) {
		slog.InfoContext(ctx, "Ignoring PCR because it is not assigned to this replica",
			slog.String("key", key),
		)
		c.pcrQueue.AddRateLimited(key)
		return true
	}
	if err != nil {
		slog.ErrorContext(ctx, "Error while handling PodCertificateRequest",
			slog.String("err", err.Error()),
			slog.String("key", key),
		)
		c.pcrQueue.AddRateLimited(key)
		return true
	}

	c.pcrQueue.Forget(key)
	return true
}

func (c *Controller) handlePCR(ctx context.Context, pcr *certsv1beta1.PodCertificateRequest) error {
	if pcr.Spec.SignerName != c.handler.SignerName() {
		// Return nil, since we are not going to magically start supporting this
		// signer name by retaining the cert in the workqueue.
		return nil
	}

	// PodCertificateRequests don't have an approval stage, and the node
	// restriction / isolation check is handled by kube-apiserver.

	// Is the PCR already signed?
	if pcr.Status.CertificateChain != "" {
		return nil
	}

	if !c.hasher.AssignedToThisReplica(ctx, pcr.ObjectMeta.Namespace+"/"+pcr.ObjectMeta.Name) {
		return rendezvous.ErrNotAssigned
	}

	lifetime := 24 * time.Hour
	requestedLifetime := time.Duration(*pcr.Spec.MaxExpirationSeconds) * time.Second
	if requestedLifetime < lifetime {
		lifetime = requestedLifetime
	}

	notBefore := c.clock.Now().Add(-2 * time.Minute)
	notAfter := notBefore.Add(lifetime)
	beginRefreshAt := notAfter.Add(-30 * time.Minute)

	chain, err := c.handler.MakeCert(ctx, notBefore, notAfter, pcr)
	if err != nil {
		return fmt.Errorf("while converting PodCertificateRequest to x509.Certificate chain: %w", err)
	}

	chainPEM := &bytes.Buffer{}
	for _, cert := range chain {
		err = pem.Encode(chainPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return fmt.Errorf("while encoding certificate to PEM: %w", err)
		}
	}

	// Don't modify the copy in the informer cache.
	pcr = pcr.DeepCopy()
	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               certsv1beta1.PodCertificateRequestConditionTypeIssued,
			Status:             metav1.ConditionTrue,
			Reason:             "Reason",
			Message:            "Issued",
			LastTransitionTime: metav1.NewTime(c.clock.Now()),
		},
	}
	pcr.Status.CertificateChain = chainPEM.String()
	pcr.Status.NotBefore = ptr.To(metav1.NewTime(notBefore))
	pcr.Status.BeginRefreshAt = ptr.To(metav1.NewTime(beginRefreshAt))
	pcr.Status.NotAfter = ptr.To(metav1.NewTime(notAfter))

	_, err = c.kc.CertificatesV1beta1().PodCertificateRequests(pcr.ObjectMeta.Namespace).UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("while updating PodCertificateRequest: %w", err)
	}

	return nil
}

func (c *Controller) ensureBundle(ctx context.Context) {
	// Only one replica should try to maintain the trust bundles.
	if !c.hasher.AssignedToThisReplica(ctx, "maintain-trust-bundles") {
		return
	}

	wantCTBs := c.handler.DesiredClusterTrustBundles()

	for _, wantCTB := range wantCTBs {
		ctb, err := c.kc.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, wantCTB.ObjectMeta.Name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			_, err = c.kc.CertificatesV1beta1().ClusterTrustBundles().Create(ctx, wantCTB, metav1.CreateOptions{})
			if err != nil {
				slog.ErrorContext(ctx, "Error while creating ClusterTrustBundle",
					slog.String("err", err.Error()),
					slog.String("key", wantCTB.ObjectMeta.Name),
				)
				return
			}
			return
		} else if err != nil {
			slog.ErrorContext(ctx, "Error while getting ClusterTrustBundle",
				slog.String("err", err.Error()),
				slog.String("key", wantCTB.ObjectMeta.Name),
			)
			return
		}

		if apiequality.Semantic.DeepEqual(wantCTB.Labels, ctb.Labels) && apiequality.Semantic.DeepEqual(wantCTB.Spec, ctb.Spec) {
			slog.InfoContext(ctx, "ClusterTrustBundle already in correct state",
				slog.String("key", wantCTB.ObjectMeta.Name),
			)
		}

		ctb = ctb.DeepCopy()
		ctb.ObjectMeta.Labels = wantCTB.Labels
		ctb.Spec.TrustBundle = wantCTB.Spec.TrustBundle

		_, err = c.kc.CertificatesV1beta1().ClusterTrustBundles().Update(ctx, ctb, metav1.UpdateOptions{})
		if err != nil {
			slog.ErrorContext(ctx, "Error while updating ClusterTrustBundle",
				slog.String("err", err.Error()),
				slog.String("key", wantCTB.ObjectMeta.Name),
			)
		}
	}
}
