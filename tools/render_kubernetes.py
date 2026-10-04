"""Render the reviewed, fixed single-node Kubernetes topology (no secrets)."""

from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
compose = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
ns = "tracehawk"
docs = []


def add(kind, name, spec=None, **extra):
    d = {
        "apiVersion": (
            "apps/v1"
            if kind in ("Deployment", "StatefulSet")
            else (
                "batch/v1"
                if kind == "Job"
                else "networking.k8s.io/v1" if kind == "NetworkPolicy" else "v1"
            )
        ),
        "kind": kind,
        "metadata": {
            "name": name,
            **(
                {"namespace": ns}
                if kind not in ("Namespace", "PersistentVolume")
                else {}
            ),
        },
        **extra,
    }
    if spec is not None:
        d["spec"] = spec
    docs.append(d)
    return d


add(
    "Namespace",
    ns,
    metadata={
        "name": ns,
        "labels": {
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "v1.35",
            "pod-security.kubernetes.io/audit": "restricted",
            "pod-security.kubernetes.io/warn": "restricted",
        },
    },
)
add("ServiceAccount", "workload", automountServiceAccountToken=False)
add(
    "ConfigMap",
    "runtime",
    data={
        "DB_HOST": "postgres",
        "KAFKA_BROKERS": "kafka:9092",
        "PUBLIC_ORIGIN": "http://127.0.0.1:3102",
        "PYTHONDONTWRITEBYTECODE": "1",
    },
)
for name, uid in [
    ("database", 70),
    ("broker", 1000),
    ("collector-state", 10001),
    ("publisher-state", 10001),
    ("metrics", 65534),
    ("grafana-data", 472),
]:
    add(
        "PersistentVolume",
        "tracehawk-" + name,
        {
            "capacity": {"storage": "2Gi"},
            "volumeMode": "Filesystem",
            "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": "Retain",
            "storageClassName": "tracehawk-local",
            "hostPath": {"path": "/tracehawk-data/" + name, "type": "Directory"},
            "nodeAffinity": {
                "required": {
                    "nodeSelectorTerms": [
                        {
                            "matchExpressions": [
                                {
                                    "key": "kubernetes.io/hostname",
                                    "operator": "In",
                                    "values": ["tracehawk-control-plane"],
                                }
                            ]
                        }
                    ]
                }
            },
        },
        metadata={
            "name": "tracehawk-" + name,
            "labels": {"app.kubernetes.io/part-of": "tracehawk"},
        },
    )
    add(
        "PersistentVolumeClaim",
        name,
        {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "tracehawk-local",
            "volumeName": "tracehawk-" + name,
            "resources": {"requests": {"storage": "2Gi"}},
        },
    )
# These static hostPath capacity declarations do not impose filesystem quotas.
add(
    "ResourceQuota",
    "budget",
    {
        "hard": {
            "requests.cpu": "4",
            "requests.memory": "2Gi",
            "limits.cpu": "12",
            "limits.memory": "3Gi",
            "pods": "20",
            "persistentvolumeclaims": "6",
            "requests.storage": "12Gi",
        }
    },
)


def secret(key):
    return {
        "name": key,
        "valueFrom": {"secretKeyRef": {"name": "runtime-secrets", "key": key}},
    }


def env(k, v):
    return {"name": k, "value": str(v)}


def probe(port, path):
    return {
        "httpGet": {"path": path, "port": port},
        "periodSeconds": 5,
        "timeoutSeconds": 3,
        "failureThreshold": 3,
    }


def execprobe(command):
    return {
        "exec": {"command": command},
        "periodSeconds": 10,
        "timeoutSeconds": 8,
        "failureThreshold": 3,
    }


def workload(
    name,
    uid,
    memory,
    cpu,
    request_memory,
    request_cpu,
    port=None,
    cmd=None,
    envs=None,
    volumes=None,
    mounts=None,
    readiness=None,
    liveness=None,
    stateful=False,
):
    c = {
        "name": name,
        "image": compose[name]["image"],
        "imagePullPolicy": "Never",
        "resources": {
            "requests": {"memory": request_memory, "cpu": request_cpu},
            "limits": {"memory": memory, "cpu": cpu},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "env": envs or [],
    }
    if cmd:
        c["command"] = cmd
    if port:
        c["ports"] = [{"containerPort": port}]
    c["volumeMounts"] = [{"name": "temp", "mountPath": "/tmp"}] + (mounts or [])
    if readiness:
        c["readinessProbe"] = readiness
    if liveness:
        c["livenessProbe"] = liveness
    startup = liveness or readiness
    if startup:
        c["startupProbe"] = {**startup, "failureThreshold": 60}
    pod = {
        "serviceAccountName": "workload",
        "automountServiceAccountToken": False,
        "terminationGracePeriodSeconds": 35,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": uid,
            "runAsGroup": uid,
            "fsGroup": uid,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [c],
        "volumes": [{"name": "temp", "emptyDir": {"sizeLimit": "64Mi"}}]
        + (volumes or []),
    }
    spec = {
        "replicas": 1,
        "selector": {"matchLabels": {"app": name}},
        "template": {
            "metadata": {
                "labels": {"app": name, "app.kubernetes.io/part-of": "tracehawk"}
            },
            "spec": pod,
        },
    }
    if stateful:
        spec["serviceName"] = name
    else:
        spec["strategy"] = {"type": "Recreate"}
    add("StatefulSet" if stateful else "Deployment", name, spec)
    if port:
        add(
            "Service",
            name,
            {
                "type": "ClusterIP",
                **(
                    {"clusterIP": "None", "publishNotReadyAddresses": True}
                    if name == "kafka"
                    else {}
                ),
                "selector": {"app": name},
                "ports": (
                    [
                        {"name": "broker", "port": 9092, "targetPort": 9092},
                        {"name": "controller", "port": 9093, "targetPort": 9093},
                    ]
                    if name == "kafka"
                    else [{"port": port, "targetPort": port}]
                ),
            },
        )
    return pod, c


def pvc(name, path):
    return (
        [{"name": name, "persistentVolumeClaim": {"claimName": name}}],
        [{"name": name, "mountPath": path}],
    )


pv, pm = pvc("database", "/var/lib/postgresql/data")
pgprobe = execprobe(["pg_isready", "-U", "tracehawk", "-d", "tracehawk"])
workload(
    "postgres",
    70,
    "384Mi",
    "1",
    "128Mi",
    "100m",
    5432,
    envs=[
        env("POSTGRES_DB", "tracehawk"),
        env("POSTGRES_USER", "tracehawk"),
        env("PGDATA", "/var/lib/postgresql/data/pgdata"),
        secret("POSTGRES_PASSWORD"),
    ],
    volumes=pv + [{"name": "pg-socket", "emptyDir": {"sizeLimit": "16Mi"}}],
    mounts=pm + [{"name": "pg-socket", "mountPath": "/var/run/postgresql"}],
    readiness=pgprobe,
    liveness=pgprobe,
    stateful=True,
)
kv, km = pvc("broker", "/var/lib/kafka/data")
ke = compose["kafka"]["environment"]
# Stable single-broker cluster identity across recreation; do not change after formatting.
ke["CLUSTER_ID"] = "MkU3OEVBNTcwNTJENDM2Qk"
ke["LOG_DIR"] = "/tmp/kafka-logs"
ke["KAFKA_GC_LOG_OPTS"] = "-Xlog:gc*:stdout:time"
kprobe = execprobe(
    ["/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", "kafka:9092", "--list"]
)
workload(
    "kafka",
    1000,
    "768Mi",
    "2",
    "384Mi",
    "250m",
    9092,
    envs=[env(k, v) for k, v in ke.items()],
    volumes=kv + [{"name": "kafka-config", "emptyDir": {"sizeLimit": "16Mi"}}],
    mounts=km + [{"name": "kafka-config", "mountPath": "/opt/kafka/config"}],
    readiness=kprobe,
    liveness=execprobe(["bash", "-c", "kill -0 1"]),
    stateful=True,
)
api_env = [
    secret(k)
    for k in (
        "POSTGRES_PASSWORD",
        "INTERNAL_TOKEN",
        "OPERATOR_PASSWORD",
        "ANALYST_PASSWORD",
    )
]
pod, c = workload(
    "api",
    10001,
    "256Mi",
    "1",
    "96Mi",
    "100m",
    8100,
    envs=api_env,
    readiness=probe(8100, "/health/ready"),
    liveness=probe(8100, "/health/live"),
)
c["envFrom"] = [{"configMapRef": {"name": "runtime"}}]
pod["initContainers"] = [
    {
        "name": "wait-database",
        "image": compose["api"]["image"],
        "imagePullPolicy": "Never",
        "command": [
            "python",
            "-c",
            "import time;from tracehawk.core import db\nwhile True:\n try:\n  c=db();c.close();break\n except Exception:time.sleep(1)",
        ],
        "env": [secret("POSTGRES_PASSWORD")],
        "envFrom": [{"configMapRef": {"name": "runtime"}}],
        "resources": {
            "requests": {"memory": "32Mi", "cpu": "50m"},
            "limits": {"memory": "128Mi", "cpu": "500m"},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
    }
]

# Explicit topic initialization avoids auto-created single-partition topics.
jobpod = {
    "serviceAccountName": "workload",
    "automountServiceAccountToken": False,
    "restartPolicy": "OnFailure",
    "securityContext": {
        "runAsNonRoot": True,
        "runAsUser": 1000,
        "runAsGroup": 1000,
        "seccompProfile": {"type": "RuntimeDefault"},
    },
    "containers": [
        {
            "name": "topics",
            "image": compose["kafka"]["image"],
            "imagePullPolicy": "Never",
            "command": ["/bin/sh", "-c"],
            "args": [
                "until /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list >/dev/null 2>&1; do sleep 3; done; "
                + compose["topics"]["command"][0].replace("$$topic", "$topic")
            ],
            "resources": {
                "requests": {"memory": "128Mi", "cpu": "100m"},
                "limits": {"memory": "384Mi", "cpu": "1"},
            },
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
            "volumeMounts": [{"name": "temp", "mountPath": "/tmp"}],
        }
    ],
    "volumes": [{"name": "temp", "emptyDir": {"sizeLimit": "64Mi"}}],
}
add(
    "Job",
    "topics",
    {
        "backoffLimit": 4,
        "activeDeadlineSeconds": 600,
        "template": {"metadata": {"labels": {"app": "topics"}}, "spec": jobpod},
    },
)
for name, mem in [
    ("detector", "256Mi"),
    ("detector-b", "192Mi"),
    ("publisher", "128Mi"),
]:
    vs, ms = pvc("publisher-state", "/state") if name == "publisher" else ([], [])
    pod, c = workload(
        name,
        10001,
        mem,
        "1",
        "48Mi",
        "100m",
        9100,
        cmd=compose[name]["command"],
        envs=[secret("POSTGRES_PASSWORD")]
        + (
            [env("WORKER_ID", compose[name]["environment"]["WORKER_ID"])]
            if name.startswith("detector")
            else []
        ),
        volumes=vs,
        mounts=ms,
        readiness=probe(9100, "/health/ready"),
        liveness=probe(9100, "/health/live"),
    )
    c["envFrom"] = [{"configMapRef": {"name": "runtime"}}]
cv, cm = pvc("collector-state", "/state")
workload(
    "collector",
    10001,
    "128Mi",
    "1",
    "32Mi",
    "100m",
    9100,
    envs=[secret("INTERNAL_TOKEN")],
    volumes=cv,
    mounts=cm,
    readiness=probe(9100, "/health/ready"),
    liveness=probe(9100, "/health/live"),
)
workload(
    "console",
    1000,
    "128Mi",
    "1",
    "48Mi",
    "100m",
    3100,
    envs=[env("GRAFANA_URL", "http://127.0.0.1:3103/d/tracehawk-operations")],
    readiness=probe(3100, "/health/live"),
    liveness=probe(3100, "/health/live"),
)
add(
    "ConfigMap",
    "monitoring",
    data={
        "prometheus.yml": (
            ROOT / "infrastructure/monitoring/prometheus.yml"
        ).read_text(),
        "datasources.yml": (
            ROOT
            / "infrastructure/monitoring/grafana/provisioning/datasources/tracehawk.yml"
        ).read_text(),
        "dashboards.yml": (
            ROOT
            / "infrastructure/monitoring/grafana/provisioning/dashboards/tracehawk.yml"
        ).read_text(),
        "operations.json": (
            ROOT / "infrastructure/monitoring/grafana/dashboards/operations.json"
        ).read_text(),
    },
)
pv, pm = pvc("metrics", "/prometheus")
workload(
    "prometheus",
    65534,
    "192Mi",
    "500m",
    "64Mi",
    "100m",
    9090,
    cmd=["/bin/prometheus", *compose["prometheus"]["command"]],
    volumes=pv + [{"name": "config", "configMap": {"name": "monitoring"}}],
    mounts=pm
    + [
        {
            "name": "config",
            "mountPath": "/etc/prometheus/prometheus.yml",
            "subPath": "prometheus.yml",
            "readOnly": True,
        }
    ],
    readiness=probe(9090, "/-/ready"),
    liveness=probe(9090, "/-/healthy"),
)
gv, gm = pvc("grafana-data", "/var/lib/grafana")
compose["grafana"]["environment"].update(
    {
        "GF_PLUGINS_PREINSTALL_DISABLED": "true",
        "GF_PLUGINS_PUBLIC_KEY_RETRIEVAL_DISABLED": "true",
    }
)
workload(
    "grafana",
    472,
    "256Mi",
    "500m",
    "96Mi",
    "100m",
    3000,
    envs=[
        env(k, v)
        for k, v in compose["grafana"]["environment"].items()
        if k != "GF_SECURITY_ADMIN_PASSWORD"
    ]
    + [
        {
            "name": "GF_SECURITY_ADMIN_PASSWORD",
            "valueFrom": {
                "secretKeyRef": {"name": "runtime-secrets", "key": "OPERATOR_PASSWORD"}
            },
        }
    ],
    volumes=gv + [{"name": "config", "configMap": {"name": "monitoring"}}],
    mounts=gm
    + [
        {"name": "config", "mountPath": path, "subPath": key, "readOnly": True}
        for path, key in [
            ("/etc/grafana/provisioning/datasources/tracehawk.yml", "datasources.yml"),
            ("/etc/grafana/provisioning/dashboards/tracehawk.yml", "dashboards.yml"),
            ("/var/lib/grafana/dashboards/operations.json", "operations.json"),
        ]
    ],
    readiness=probe(3000, "/api/health"),
    liveness=probe(3000, "/api/health"),
)
# Default deny both directions. Peers require matching namespace AND app labels.
add(
    "NetworkPolicy",
    "default-deny",
    {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
)
peer = lambda app: {
    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
    "podSelector": {"matchLabels": {"app": app}},
}
port = lambda n: {"protocol": "TCP", "port": n}
add(
    "NetworkPolicy",
    "dns",
    {
        "podSelector": {},
        "policyTypes": ["Egress"],
        "egress": [
            {
                "to": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "kube-system"
                            }
                        },
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    }
                ],
                "ports": [{"protocol": "UDP", "port": 53}, port(53)],
            }
        ],
    },
)
edges = [
    ("console", "api", 8100),
    ("collector", "api", 8100),
    ("api", "postgres", 5432),
    ("detector", "postgres", 5432),
    ("detector-b", "postgres", 5432),
    ("publisher", "postgres", 5432),
    ("collector", "kafka", 9092),
    ("detector", "kafka", 9092),
    ("detector-b", "kafka", 9092),
    ("publisher", "kafka", 9092),
    ("topics", "kafka", 9092),
    ("kafka", "kafka", 9092),
    ("kafka", "kafka", 9093),
    ("grafana", "prometheus", 9090),
] + [
    ("prometheus", x, 9100)
    for x in ("collector", "detector", "detector-b", "publisher")
]
for app in sorted(set(x for e in edges for x in e[:2])):
    add(
        "NetworkPolicy",
        "allow-" + app,
        {
            "podSelector": {"matchLabels": {"app": app}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                {"from": [peer(src)], "ports": [port(p)]}
                for src, dst, p in edges
                if dst == app
            ],
            "egress": [
                {"to": [peer(dst)], "ports": [port(p)]}
                for src, dst, p in edges
                if src == app
            ],
        },
    )
# Console/Grafana are accessed by loopback-bound kubectl port-forward (node traffic).
(ROOT / "infrastructure/kubernetes/resources.yaml").write_text(
    yaml.safe_dump_all(docs, sort_keys=False)
)
(ROOT / "infrastructure/kubernetes/kustomization.yaml").write_text(
    "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - resources.yaml\n"
)
print(f"Rendered {len(docs)} reviewed resources; no secret values.")
