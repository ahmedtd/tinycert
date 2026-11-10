# TinyCert: Educational, Bare-Bones K8s Certificates

Kubernetes 1.34 shipped Pod Certificates, a new feature that streamlines issuing
X.509 certificates to pods.  This repository specifies a few example signers to
show how Pod Certificates and Cluster Trust Bundles can be used together to
enable easy TLS and mTLS between workloads running in the same (or different)
clusters.

## Getting Started (Kind)

### Cluster Creation (Kind)

Pod Certificates and Cluster Trust Bundles are not enabled by default, so the
easiest way to test them out is to create a local test cluster using
[Kind](https://kind.sigs.k8s.io/).

`kind/kind-config.yaml` is a cluster configuration that enables all the necessary flags to use Pod Certificates and Cluster Trust Bundles.
```
kind create cluster --image=kindest/node:latest --config=kind/kind-config.yaml
```

### Build and Deploy

The images in this repository are built with [ko](https://ko.build/), which
simplifies building images and deploying manifests.

Build and deploy the signer controller:
```
KO_DOCKER_REPO=<your-repo> go tool ko apply -f controller-manifests
```

The signer controller will crashloop until you create the root certificates and
keys for each of the signers:
```
go run ./cmd/tinycerttool make-ca-pool-secret --namespace tinycert-system --name service-dns-ca-pool --ca-id 1
go run ./cmd/tinycerttool make-ca-pool-secret --namespace tinycert-system --name spiffe-ca-pool --ca-id 1
```

If you like, you can now deploy some example applications that use certificates
issued by the signer controller in different configurations.
```
KO_DOCKER_REPO=<your-repo> go tool ko apply -f example-manifests/
```

## Signers

### ahmedtd.github.io/tinycert-service

This signer issues "standard" server TLS certificates for the DNS names of all
Services the pod is part of.  Note that the set of Services that a pod is part
of can change over time as Services are added and deleted, or their label
selectors are changed.  These updates will not be reflected until the next time
the certificate is refreshed.

This signer distributes its trust anchors using signer-linked
ClusterTrustBundles.  Use the label selector
`ahmedtd.github.io/tinycert-canarying=live`.

Clients do not need any special certificate validation logic, beyond configuring
the proper trust bundle.  If they connect to a Service via the DNS name
`<service>.<namespace>.svc`, then standard TLS certificate validation will work.

The certificates issued by this signer have the following properties:
* The Subject field is entirely empty
* For each Service that the Pod is part of at the time the certificate is
  issued, there is one DNS Subject Alternate Name of the form
  `<service-name>.<service-namespace>.svc`.
* There are no other Subject Alternate Names.
* The maximum lifetime is 24 hours.
* The certificates are backdated by an unspecified amount sufficient to cover
  reasonable clock skew.

These certificates cannot meaningfully be used as client certificates.

### ahmedtd.github.io/tinycert-spiffe

This signer issues SPIFFE certificates to pods, with SPIFFE identities of the form `spiffe://<trust-domain>/service-account/<pod-namespace>/<pod-service-account>`.
* `trust-domain` is a configurable value for the SPIFFE trust domain.  In the
  demo, it defaults to `cluster.local`, but in a real deployment you will need
  to choose a unique value that makes sense, especially if you are expecting
  communication across multiple clusters.
* `pod-namespace` is the namespace of the Pod that the certificate was issued to.
* `pod-service-account` is the name of the ServiceAccount that the Pod is running as.

This signer distributes its trust anchors using signer-linked
ClusterTrustBundles.  Use the label selectors:
* `ahmedtd.github.io/tinycert-canarying=live`
* `ahmedtd.github.io/tinycert-workload-trust-domain=<trust-domain>`
* `ahmedtd.github.io/tinycert-peer-trust-domain=<trust-domain>`

## Examples

In namespace `tinycert-spiffe-demo`, you'll find a client-server pair that both
use a certificates issued by `ahmedtd.github.io/tinycert-spiffe`.  The client is
configured to require that the server present a particular SPIFFE ID, and the
server logs the SPIFFE ID presented by the client.


