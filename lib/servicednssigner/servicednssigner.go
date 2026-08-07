package servicednssigner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/ahmedtd/tinycert/lib/localca"
	"github.com/ahmedtd/tinycert/lib/signercontroller"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const Name = "ahmedtd.github.io/tinycert-service"

const CTBPrefix = "ahmedtd.github.io:tinycert-service:"

type Impl struct {
	kc     kubernetes.Interface
	caPool *localca.Pool
}

func NewImpl(kc kubernetes.Interface, caPool *localca.Pool) *Impl {
	return &Impl{
		kc:     kc,
		caPool: caPool,
	}
}

var _ signercontroller.SignerImpl = (*Impl)(nil)

func (h *Impl) SignerName() string {
	return Name
}

func (h *Impl) DesiredClusterTrustBundles() []*certsv1beta1.ClusterTrustBundle {
	name := CTBPrefix + "primary-bundle"

	wantTrustBundle := bytes.Buffer{}
	for _, ca := range h.caPool.CAs {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.RootCertificate.Raw,
		})
		_, _ = wantTrustBundle.Write(block)
	}

	wantCTB := &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"ahmedtd.github.io/tinycert-canarying": "live",
			},
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  Name,
			TrustBundle: wantTrustBundle.String(),
		},
	}

	return []*certsv1beta1.ClusterTrustBundle{
		wantCTB,
	}
}

func (h *Impl) CAPool() *localca.Pool {
	return h.caPool
}

func (h *Impl) MakeCert(ctx context.Context, notBefore, notAfter time.Time, pcr *certsv1beta1.PodCertificateRequest) ([]*x509.Certificate, error) {
	// TODO: Switch from live reads to indexer

	// If our signer had a policy about which pods are allowed to request
	// certificates, it would be implemented here.

	svcs, err := h.kc.CoreV1().Services(pcr.ObjectMeta.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("while listing services: %w", err)
	}

	// TODO: Looping over every service isn't great.  Maintain an index of pod
	// to covering services.

	dnsNames := []string{}
	for _, svc := range svcs.Items {
		switch svc.Spec.Type {
		case corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort, corev1.ServiceTypeLoadBalancer:
			// ok
		default:
			// This service type doesn't select pods using a label selector.
			continue
		}

		// Find the set of pods that the service selects.
		matchedPods, err := h.kc.CoreV1().Pods(pcr.ObjectMeta.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector}),
		})
		if err != nil {
			return nil, fmt.Errorf("while selecting pods for service %q: %w", pcr.ObjectMeta.Namespace+"/"+svc.ObjectMeta.Name, err)
		}

		for _, matchedPod := range matchedPods.Items {
			if matchedPod.ObjectMeta.Name == pcr.Spec.PodName && matchedPod.ObjectMeta.UID == pcr.Spec.PodUID {
				// TODO: I'm making some assumptions about the DNS names that
				// resolve to a given Service.  I know at least one
				// configuration that I suspect doesn't match these assumptions
				// --- GKE with VPC-scoped Cloud DNS [1].
				//
				// [1] https://cloud.google.com/kubernetes-engine/docs/how-to/cloud-dns#vpc_scope_dns
				name := fmt.Sprintf("%s.%s.svc", svc.ObjectMeta.Name, svc.ObjectMeta.Namespace)
				dnsNames = append(dnsNames, name)
			}
		}
	}

	parsedCSR, err := x509.ParseCertificateRequest(pcr.Spec.StubPKCS10Request)
	if err != nil {
		return nil, fmt.Errorf("while parsing CSR from request: %w", err)
	}

	// If our signer had an opinion on which key types were allowable, it would
	// check subjectPublicKey, and deny the PCR with a SuggestedKeyType
	// condition on it.

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	subjectCertDER, err := x509.CreateCertificate(rand.Reader, template, h.caPool.CAs[0].RootCertificate, parsedCSR.PublicKey, h.caPool.CAs[0].SigningKey)
	if err != nil {
		return nil, fmt.Errorf("while signing subject cert: %w", err)
	}

	leafCert, err := x509.ParseCertificate(subjectCertDER)
	if err != nil {
		return nil, fmt.Errorf("while parsing leaf cert: %w", err)
	}

	ret := []*x509.Certificate{leafCert}
	ret = append(ret, h.caPool.CAs[0].IntermediateCertificates...)

	return ret, nil
}
