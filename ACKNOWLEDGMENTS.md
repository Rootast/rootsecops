# Acknowledgments

Created and maintained by **[Arash Shahbazi](https://github.com/Rootast)**.

RootSecOps provides the orchestration, web interface, and result normalization.
Its analysis depends on the work of these independent projects and communities:

| Project | Role |
| --- | --- |
| [Syft](https://github.com/anchore/syft) | Software bill of materials |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerability analysis |
| [Grype](https://github.com/anchore/grype) | Vulnerability analysis |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Open source vulnerability analysis |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secret detection |
| [ClamAV](https://github.com/Cisco-Talos/clamav) | Malware signatures |
| [YARA](https://github.com/VirusTotal/yara) | Pattern-matching rules |
| [Hadolint](https://github.com/hadolint/hadolint) | Dockerfile linting |
| [Checkov](https://github.com/bridgecrewio/checkov) | Infrastructure checks |
| [KICS](https://github.com/Checkmarx/kics) | Infrastructure checks |
| [Grant](https://github.com/anchore/grant) | License information |
| [ExifTool](https://exiftool.org/) / [Poppler](https://poppler.freedesktop.org/) | File metadata |
| [Anchore](https://github.com/anchore) / [Clair](https://github.com/quay/clair) | Optional external integrations |

The application also uses Django, Django REST Framework, Celery, PostgreSQL,
Redis, Next.js, React, Tailwind CSS, Radix UI, Lucide, Recharts, and other
dependencies listed in the manifests.

The RootSecOps MIT license covers this project's original code, not a
relicensing of third-party software, rules, databases, or container contents.
Review their upstream licenses and redistribution conditions. Listing a project
here does not imply sponsorship, partnership, endorsement, or authorship by its
maintainers.
