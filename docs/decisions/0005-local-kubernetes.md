# ADR 0005: Local Kubernetes with enforced network boundaries and host-retained state

Status: implemented and locally verified.

Use a dedicated kind v0.31.0 / Kubernetes v1.35.0 single-node cluster. Calico v3.33.0 supplies CNI and policy enforcement. The upstream manifest is vendored with its license, source/hash record and registry digest pins. TraceHawk uses the same locally built application images in Compose and Kubernetes; no registry publication is needed.

A separate kubeconfig, credentials and data directory keep this experiment separate from Compose and other projects. A helper verifies the dedicated node's cluster label and exact data mount before stopping/deleting it. It temporarily stops only TraceHawk Compose services, preserving their named volumes.

Default-deny ingress/egress plus namespace-and-app selectors permit the required service paths and DNS. Kafka uses a private headless service publishing not-ready addresses for initial broker/controller communication; otherwise its controller connection depends on broker readiness. This service exposes no host port. Only loopback-bound authenticated-console/Grafana port-forwards are offered to a developer.

Application, database and monitoring pods meet Kubernetes' Restricted admission policy: non-root, RuntimeDefault seccomp, dropped capabilities, no privilege escalation and no service-account token. Root filesystems are read-only, with explicit writable volumes. Calico and the kind control plane are privileged infrastructure outside that application namespace; the host/cluster administrator remains trusted.

Six statically bound local PVs use Retain and an explicit node mount. The host directory survives deletion of the node and its Kubernetes objects, so new PVs can bind the retained files on recreation. This is a local single-node storage demonstration, not a CSI/HA/backup design. HostPath capacity declarations do not enforce disk quotas. Node loss with host-directory loss is outside the recovery guarantee.

Real tests cover default/allowed connections, a foreign namespace with a spoofed application label, restricted container settings, unmounted tokens/denied Secret RBAC, loaded detector restart, database/broker pod replacement, whole-cluster recreation and replay after recreation. See `docs/phase-5/kubernetes.json` and the phase guide.
