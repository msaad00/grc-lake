"""Immutable content-addressed S3 blobs and verified private materializations.

A worker never mutates a shared file. Uploading uncommitted objects cannot change
what readers see; only a fenced PostgreSQL manifest publication does that.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from contextlib import suppress
from itertools import islice
from pathlib import Path, PurePosixPath

from security_lakehouse.distributed.config import ClusterConfig
from security_lakehouse.io import file_sha256


class IntegrityError(ValueError):
    """Object contents or a workspace boundary failed verification."""


def _relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(p in {".", ".."} for p in value.split("/")) or "\\" in value:
        raise IntegrityError("unsafe relative artifact path")
    return path


class ObjectStore:
    def __init__(self, config: ClusterConfig, *, client=None):
        self.config = config
        if client is None:
            import boto3
            from botocore.config import Config  # type: ignore[import-untyped]

            client = boto3.client(
                "s3",
                endpoint_url=config.endpoint,
                region_name=config.region,
                config=Config(
                    signature_version="s3v4",
                    connect_timeout=5,
                    read_timeout=60,
                    retries={"max_attempts": 3, "mode": "standard"},
                ),
            )
        self.client = client

    def key(self, tenant_id: str, digest: str) -> str:
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise IntegrityError("invalid object digest")
        return f"{self.config.prefix_for(tenant_id)}/objects/sha256/{digest[:2]}/{digest}"

    def put(self, tenant_id: str, path: Path) -> dict:
        from botocore.exceptions import ClientError  # type: ignore[import-untyped]

        digest = file_sha256(path)
        size = path.stat().st_size
        key = self.key(tenant_id, digest)
        try:
            if size <= 32 * 1024**2:
                with path.open("rb") as body:
                    self.client.put_object(
                        Bucket=self.config.bucket,
                        Key=key,
                        Body=body,
                        IfNoneMatch="*",
                        Metadata={"sha256": digest},
                        ContentLength=size,
                    )
            else:
                self._multipart(key, path, digest)
        except ClientError as exc:
            if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 412:
                raise
            # Verify existing bytes; never trust a supplied metadata hash alone.
            with tempfile.TemporaryDirectory(prefix="grc-object-verify-") as folder:
                self.get(tenant_id, {"sha256": digest, "size": size}, Path(folder) / "blob")
        if file_sha256(path) != digest:
            raise IntegrityError("artifact changed during upload")
        return {"sha256": digest, "size": size}

    def _multipart(self, key: str, path: Path, digest: str) -> None:
        upload = self.client.create_multipart_upload(Bucket=self.config.bucket, Key=key, Metadata={"sha256": digest})[
            "UploadId"
        ]
        try:
            parts = []
            with path.open("rb") as source:
                for number, data in enumerate(iter(lambda: source.read(8 * 1024**2), b""), 1):
                    result = self.client.upload_part(
                        Bucket=self.config.bucket, Key=key, UploadId=upload, PartNumber=number, Body=data
                    )
                    parts.append({"PartNumber": number, "ETag": result["ETag"]})
            self.client.complete_multipart_upload(
                Bucket=self.config.bucket, Key=key, UploadId=upload, MultipartUpload={"Parts": parts}, IfNoneMatch="*"
            )
        except BaseException:
            with suppress(Exception):
                self.client.abort_multipart_upload(Bucket=self.config.bucket, Key=key, UploadId=upload)
            raise

    def get(self, tenant_id: str, entry: dict, target: Path) -> None:
        size = entry.get("size")
        if type(size) is not int or not 0 <= size <= self.config.workspace_limit:
            raise IntegrityError("invalid object size")
        key = self.key(tenant_id, entry.get("sha256", ""))
        result = self.client.get_object(Bucket=self.config.bucket, Key=key)
        body = result["Body"]
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".download")
        digest = hashlib.sha256()
        count = 0
        try:
            if result.get("ContentLength") != size:
                raise IntegrityError("object length differs from publication")
            with temporary.open("xb") as output:
                os.chmod(temporary, 0o600)
                for chunk in iter(lambda: body.read(1024**2), b""):
                    count += len(chunk)
                    if count > size:
                        raise IntegrityError("object exceeds declared size")
                    digest.update(chunk)
                    output.write(chunk)
            if count != size or digest.hexdigest() != entry["sha256"]:
                raise IntegrityError("object digest differs from publication")
            os.replace(temporary, target)
        finally:
            body.close()
            temporary.unlink(missing_ok=True)

    def snapshot(self, tenant_id: str, root: Path, *, previous: dict | None = None) -> dict:
        root = root.resolve()
        files: dict[str, dict | None] = {}
        links: dict[str, str] = {}
        total = 0
        paths = list(islice(root.rglob("*"), self.config.file_limit + 1))
        if len(paths) > self.config.file_limit:
            raise IntegrityError("workspace has too many entries")
        # Validate the complete layout and budget before the first upload.
        for path in paths:
            relative = path.relative_to(root).as_posix()
            _relative(relative)
            if path.is_symlink():
                link = path.readlink()
                if link.is_absolute() or not path.resolve().is_relative_to(root):
                    raise IntegrityError("artifact symlink escapes the workspace")
                links[relative] = link.as_posix()
            elif path.is_file():
                if path.name.endswith(".lock") or path.name == ".DS_Store":
                    continue
                total += path.stat().st_size
                if total > self.config.workspace_limit:
                    raise IntegrityError("workspace exceeds configured size")
                files[relative] = None
            elif not path.is_dir():
                raise IntegrityError("workspace contains a special file")
        for relative in files:
            path = root / relative
            entry = {"sha256": file_sha256(path), "size": path.stat().st_size}
            old = (previous or {}).get("files", {}).get(relative)
            # The previous publication was verified during restore. Reuse its
            # immutable reference when the private copy is byte-for-byte equal.
            files[relative] = entry if entry == old else self.put(tenant_id, path)
        shares = set()
        share_file = root / "gold/trust_shares.jsonl"
        if share_file.is_file():
            from security_lakehouse.io import iter_jsonl

            shares = {row["token_sha256"] for row in iter_jsonl(share_file) if "token_sha256" in row}
        return {"schema": 1, "tenant_id": tenant_id, "files": files, "links": links, "shares": sorted(shares)}

    def restore(self, tenant_id: str, manifest: dict, root: Path) -> None:
        if manifest.get("tenant_id", tenant_id) != tenant_id:
            raise IntegrityError("manifest belongs to another tenant")
        files, links = manifest.get("files", {}), manifest.get("links", {})
        if (
            not isinstance(files, dict)
            or not isinstance(links, dict)
            or len(files) + len(links) > self.config.file_limit
        ):
            raise IntegrityError("invalid artifact manifest")
        root = root.absolute()
        if root.exists() and (root.is_symlink() or any(root.iterdir())):
            raise IntegrityError("restore requires a new empty private directory")
        total = 0
        names = set(files) | set(links)
        for name in names:
            path = _relative(name)
            if any(parent.as_posix() in names for parent in path.parents if str(parent) != "."):
                raise IntegrityError("artifact file or link cannot be a directory parent")
        for entry in files.values():
            if not isinstance(entry, dict):
                raise IntegrityError("invalid artifact entry")
            size = entry.get("size")
            if type(size) is not int or size < 0:
                raise IntegrityError("invalid artifact size")
            total += size
            self.key(tenant_id, entry.get("sha256", ""))
        if total > self.config.workspace_limit:
            raise IntegrityError("manifest exceeds workspace size")
        for name, link in links.items():
            if (
                not isinstance(link, str)
                or Path(link).is_absolute()
                or not (root / name).parent.joinpath(link).resolve().is_relative_to(root)
            ):
                raise IntegrityError("artifact symlink escapes the workspace")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name, entry in files.items():
            self.get(tenant_id, entry, root / name)
        for name, link in links.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(link)
            if not target.resolve().is_relative_to(root):
                target.unlink()
                raise IntegrityError("artifact symlink escapes the workspace")

    def verify_conditional_writes(self) -> None:
        """Preflight both single and multipart conditions before using a provider."""
        import uuid

        from botocore.exceptions import ClientError

        key = f"clusters/{self.config.cluster_id}/preflight/{uuid.uuid4().hex}"
        try:
            with tempfile.TemporaryDirectory(prefix="grc-s3-preflight-") as folder:
                path = Path(folder) / "probe"
                path.write_bytes(b"first")
                self._multipart(key, path, hashlib.sha256(b"first").hexdigest())
                path.write_bytes(b"second")
                for multipart in (False, True):
                    try:
                        if multipart:
                            self._multipart(key, path, hashlib.sha256(b"second").hexdigest())
                        else:
                            self.client.put_object(Bucket=self.config.bucket, Key=key, Body=b"second", IfNoneMatch="*")
                    except ClientError as exc:
                        if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 412:
                            raise
                    else:
                        raise IntegrityError("object service did not enforce conditional writes")
                response = self.client.get_object(Bucket=self.config.bucket, Key=key)
                try:
                    if response["Body"].read() != b"first":
                        raise IntegrityError("object service overwrote a conditional object")
                finally:
                    response["Body"].close()
        finally:
            self.client.delete_object(Bucket=self.config.bucket, Key=key)
