import subprocess
import tarfile
import posixpath
from pathlib import Path


def container_data_filter(member: tarfile.TarInfo, destination: str):
    # Container-absolute links must resolve inside the exported root, not the host.
    if member.linkname.startswith("/"):
        target = member.linkname.lstrip("/")
        if member.issym():
            parent = posixpath.dirname(member.name.lstrip("/")) or "."
            member = member.replace(linkname=posixpath.relpath(target or ".", parent))
        elif member.islnk():
            member = member.replace(linkname=target)
    return tarfile.data_filter(member, destination)


def pull_image(image_ref: str) -> None:
    subprocess.run(["docker", "pull", image_ref], check=True, capture_output=True, text=True)


def syft_sbom(image_ref: str, output_path: str) -> None:
    subprocess.run(["syft", image_ref, "-o", "json", f"--file={output_path}"], check=True, capture_output=True, text=True)


def syft_cyclonedx_sbom(image_ref: str, output_path: str) -> None:
    subprocess.run(
        ["syft", image_ref, "-o", "cyclonedx-json", f"--file={output_path}"],
        check=True,
        capture_output=True,
        text=True,
    )


def export_image_fs(image_ref: str, workdir: Path) -> str:
    tar_path = workdir / "container_fs.tar"
    extract_dir = workdir / "fs"
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        container_id = subprocess.run(
            ["docker", "create", "--pull=missing", image_ref],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Docker create failed: {(exc.stderr or exc.stdout or str(exc))[:2000]}") from exc
    try:
        with tar_path.open("wb") as handle:
            subprocess.run(["docker", "export", container_id], check=True, stdout=handle)
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], check=False, capture_output=True, text=True)

    with tarfile.open(tar_path) as archive:
        archive.extractall(path=extract_dir, filter=container_data_filter)
    return str(extract_dir)


def clone_repo_with_token(repo_url: str, token: str, destination: str) -> None:
    auth_url = repo_url
    if token and repo_url.startswith("https://"):
        auth_url = repo_url.replace("https://", f"https://{token}@")
    subprocess.run(["git", "clone", auth_url, destination], check=True, capture_output=True, text=True)
