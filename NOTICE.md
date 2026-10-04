# Attribution

Project code and documentation use the root MIT license. Original synthetic packet captures and associated generated telemetry/labels declare CC0-1.0 in their manifests. Refer to each manifest for provenance; the captures contain fictional laboratory traffic.

The vendored Calico manifest originates from [projectcalico/calico v3.33.0](https://github.com/projectcalico/calico/tree/v3.33.0), with image references pinned to digests. Its Apache-2.0 license is preserved in `infrastructure/kubernetes/vendor/LICENSE-calico`; source URLs and hashes are recorded in `vendor/manifest.json`. Upstream software/container dependencies retain their respective licenses. The two trained Isolation Forest JSON artifacts contain models trained only on this project's synthetic data, with scikit-learn version and feature provenance recorded in each artifact.

The external repositories supplied during planning were references for architectural ideas. This repository's detector, collector, console and evaluation implementation was developed here; no code from those repositories is vendored. Development used AI-assisted coding and local verification. Claims in the README refer to executed tests and stored evidence, with unsuccessful ML and capacity results retained.
