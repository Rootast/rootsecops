# File and Dockerfile analysis

The dashboard accepts Dockerfile text/uploads and arbitrary file uploads.
Select **New Orchestrated Scan**, choose the artifact type, and submit it.

The browser sends authenticated multipart data directly to
`API_DOMAIN/api/v1/scans/`. Upload fields are `asset_type`, `target`,
`file`, and JSON-encoded `options`.

Dockerfiles use configuration/secret scanners. Files use applicable malware,
rule, metadata, and secret scanners. pdfinfo only applies to PDFs.
Disabled, unavailable, or inapplicable tools appear in task status and logs.

Files are stored under generated names in the worker's persistent
`/app/var/uploads` or `/app/var/file_sandbox` directories.
The default file analysis limit is 50 MB, configured by
`FILE_SANDBOX_MAX_UPLOAD_MB`; Nginx also enforces a request body limit.

## Security boundary

The feature named "sandbox" performs **static analysis**, not execution in an
isolated virtual machine. Uploading a file does not prove it is safe, and a
clean-looking result from one tool does not cover skipped tools.

Treat originals, extracted content, logs, and findings as sensitive.
Use synthetic samples for testing, restrict who can submit files, provision
scanner signatures, and set storage retention/resource limits for your use case.
See [SECURITY.md](SECURITY.md).
