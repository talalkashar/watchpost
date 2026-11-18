"""Kubernetes Sigma pack: each rule loads, maps an ATT&CK technique, fires, and stays quiet on look-alikes."""

import json
import unittest
from pathlib import Path

from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "kubernetes"
TS = "2026-11-18T15:04:00+00:00"


def audit(verb, code, uri, username, resource, namespace, name=None, subresource=None,
          request_object=None, spaced=False):
    """One Kubernetes audit line, compact like the apiserver, or with JSON spaces."""
    ref = {"resource": resource, "namespace": namespace, "apiVersion": "v1"}
    if name is not None:
        ref["name"] = name
    if subresource is not None:
        ref["subresource"] = subresource
    body = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "verb": verb,
        "user": {"username": username, "groups": ["system:authenticated"]},
        "objectRef": ref,
        "requestURI": uri,
        "responseStatus": {"code": code},
    }
    if request_object is not None:
        body["requestObject"] = request_object
    if spaced:
        return json.dumps(body)
    return json.dumps(body, separators=(",", ":"))


def ev(message, event_type="cloud_api_call", user="alice", src_ip="203.0.113.50", host="kube-apiserver"):
    return {"event_type": event_type, "user": user, "src_ip": src_ip, "host": host, "message": message}


# filename, rule id, technique, severity, malicious events, benign events.
CASES = [
    (
        "api_password_guessing_external.yml",
        "sigma_kubernetes_api_password_guessing_from_external",
        "T1110.001",
        "high",
        [
            ev(audit("list", 401, "/api/v1/pods", "alice", "pods", "")),
            ev(audit("get", 401, "/api/v1/secrets", "bob", "secrets", "dev", spaced=True),
               src_ip="198.51.100.8"),
        ],
        [
            ev(audit("list", 401, "/api/v1/pods", "alice", "pods", ""), src_ip="172.31.5.5"),
            ev(audit("list", 401, "/api/v1/pods", "alice", "pods", ""), src_ip="127.0.0.1"),
            ev(audit("list", 200, "/api/v1/pods", "alice", "pods", "")),
            ev("Failed password for root from 203.0.113.50 port 22 ssh2", event_type="auth_failure",
               user="root"),
        ],
    ),
    (
        "external_cloud_principal.yml",
        "sigma_kubernetes_api_call_by_external_cloud_principal",
        "T1078.004",
        "high",
        [
            ev(audit("list", 200, "/api/v1/pods", "arn:aws:sts::123456789012:assumed-role/Admin/alice",
                     "pods", "")),
            ev(audit("create", 201, "/api/v1/namespaces/dev/secrets",
                     "builder@proj.iam.gserviceaccount.com", "secrets", "dev", spaced=True),
               src_ip="198.51.100.20"),
        ],
        [
            ev(audit("list", 200, "/api/v1/pods", "arn:aws:sts::123456789012:assumed-role/Admin/alice",
                     "pods", ""), src_ip="192.168.1.9"),
            ev(audit("list", 401, "/api/v1/pods", "arn:aws:sts::123456789012:assumed-role/Admin/alice",
                     "pods", "")),
            ev(audit("list", 200, "/api/v1/pods", "kubernetes-admin", "pods", "",
                     request_object={"metadata": {"annotations": {
                         "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/node"}}})),
            ev("CreateAccessKey on iam arn:aws:iam::123456789012:user/alice code 200",
               user="arn:aws:iam::123456789012:user/alice"),
        ],
    ),
    (
        "kube_system_service_account_created.yml",
        "sigma_kube_system_service_account_created",
        "T1136.003",
        "medium",
        [
            ev(audit("create", 201, "/api/v1/namespaces/kube-system/serviceaccounts", "alice",
                     "serviceaccounts", "kube-system", name="cluster-backup")),
            ev(audit("create", 201, "/api/v1/namespaces/kube-system/serviceaccounts", "ci-bot",
                     "serviceaccounts", "kube-system", name="log-reader", spaced=True),
               user="ci-bot"),
        ],
        [
            ev(audit("create", 201, "/api/v1/namespaces/dev/serviceaccounts", "alice",
                     "serviceaccounts", "dev", name="builder")),
            ev(audit("get", 200, "/api/v1/namespaces/kube-system/serviceaccounts/default", "alice",
                     "serviceaccounts", "kube-system", name="default")),
            ev(audit("create", 201, "/api/v1/namespaces/kube-system/serviceaccounts",
                     "system:kube-controller-manager", "serviceaccounts", "kube-system", name="default"),
               user="system:kube-controller-manager"),
            ev(audit("create", 201, "/api/v1/namespaces/kube-system/serviceaccounts/default/token",
                     "alice", "serviceaccounts", "kube-system", name="default", subresource="token"),
               user="alice"),
        ],
    ),
    (
        "service_account_credential_minted.yml",
        "sigma_kubernetes_service_account_credential_minted",
        "T1098.001",
        "high",
        [
            ev(audit("create", 201, "/api/v1/namespaces/dev/serviceaccounts/builder/token", "alice",
                     "serviceaccounts", "dev", name="builder", subresource="token")),
            ev(audit("create", 201, "/api/v1/namespaces/kube-system/secrets", "alice",
                     "secrets", "kube-system", name="admin-token", spaced=True,
                     request_object={"kind": "Secret", "type": "kubernetes.io/service-account-token"}),
               user="alice"),
        ],
        [
            ev(audit("create", 201, "/api/v1/namespaces/dev/serviceaccounts/builder/token",
                     "system:node:ip-10-0-1-20", "serviceaccounts", "dev", name="builder",
                     subresource="token"),
               user="system:node:ip-10-0-1-20"),
            ev(audit("get", 200, "/api/v1/namespaces/kube-system/secrets/admin-token", "alice",
                     "secrets", "kube-system", name="admin-token",
                     request_object={"kind": "Secret", "type": "kubernetes.io/service-account-token"})),
            ev(audit("create", 201, "/api/v1/namespaces/dev/secrets", "alice", "secrets", "dev",
                     name="app-config", request_object={"kind": "Secret", "type": "Opaque"})),
            ev(audit("create", 201, "/api/v1/namespaces/kube-system/serviceaccounts", "alice",
                     "serviceaccounts", "kube-system", name="cluster-backup")),
        ],
    ),
    (
        "audit_policy_modified.yml",
        "sigma_kubernetes_audit_policy_modified_or_deleted",
        "T1562.008",
        "high",
        [
            ev(audit("patch", 200, "/api/v1/namespaces/kube-system/configmaps/audit-policy", "alice",
                     "configmaps", "kube-system", name="audit-policy")),
            ev(audit("delete", 200, "/api/v1/namespaces/kube-system/configmaps/kube-apiserver-audit",
                     "alice", "configmaps", "kube-system", name="kube-apiserver-audit", spaced=True)),
        ],
        [
            ev(audit("get", 200, "/api/v1/namespaces/kube-system/configmaps/audit-policy", "alice",
                     "configmaps", "kube-system", name="audit-policy")),
            ev(audit("patch", 200, "/api/v1/namespaces/kube-system/configmaps/coredns", "alice",
                     "configmaps", "kube-system", name="coredns")),
            ev(audit("list", 200, "/api/v1/namespaces/kube-system/configmaps", "alice",
                     "configmaps", "kube-system")),
        ],
    ),
    (
        "cluster_network_scan.yml",
        "sigma_kubernetes_cluster_network_service_scan",
        "T1046",
        "high",
        [
            ev("nmap -sS -p 1-1024 kubernetes.default.svc.cluster.local", event_type="process_start",
               user="root", src_ip=None, host="node-a"),
            ev("/usr/bin/masscan -p443 10.96.0.1", event_type="process_start", user="app",
               src_ip=None, host="worker-2"),
        ],
        [
            ev("nmap -sV -p 22 203.0.113.10", event_type="process_start", user="root",
               src_ip=None, host="node-a"),
            ev("curl -sk https://kubernetes.default.svc.cluster.local/healthz", event_type="process_start",
               user="app", src_ip=None, host="worker-2"),
            ev("GET /scan HTTP/1.1 nmap svc.cluster.local", event_type="web_request", user=None,
               src_ip="203.0.113.50", host="ingress"),
        ],
    ),
]


class KubernetesSigmaPackTests(unittest.TestCase):
    def test_pack_is_six_rules(self):
        names = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(names, sorted(case[0] for case in CASES))

    def test_each_rule_loads_fires_and_ignores_lookalikes(self):
        for name, rule_id, technique, severity, malicious, benign in CASES:
            with self.subTest(rule=name):
                compiled = sigma.compile_rule((PACK / name).read_text())
                self.assertEqual(compiled["rule_id"], rule_id)
                self.assertEqual([t["id"] for t in compiled["techniques"]], [technique])
                self.assertEqual(compiled["severity"], severity)
                params = compiled["params"]
                events = []
                for n, event in enumerate(malicious, 1):
                    self.assertTrue(sigma.matches(params, event), event["message"])
                    events.append({**event, "id": n, "ts": TS})
                base = len(events)
                for n, event in enumerate(benign, 1):
                    self.assertFalse(sigma.matches(params, event), event["message"])
                    events.append({**event, "id": base + n, "ts": TS})
                fired = {i for finding in sigma.run(events, params) for i in finding["event_ids"]}
                self.assertEqual(fired, set(range(1, len(malicious) + 1)))


if __name__ == "__main__":
    unittest.main()
