"""AWS S3 client wrappers for encrypted artifact transport."""
from __future__ import annotations

from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class S3OperationError(RuntimeError):
    """Raised when an S3 transfer cannot be completed."""


class S3StorageClient:
    """Small wrapper around boto3 S3 APIs with robust exceptions."""

    def __init__(self, region_name: str | None = None) -> None:
        self._client = boto3.client("s3", region_name=region_name)

    def upload_file(
        self,
        local_path: str,
        bucket: str,
        key: str,
        kms_key_id: str | None = None,
    ) -> None:
        source = Path(local_path)
        if not source.exists():
            raise S3OperationError(f"Local file does not exist: {source}")

        extra_args: dict[str, str] = {}
        if kms_key_id:
            extra_args["ServerSideEncryption"] = "aws:kms"
            extra_args["SSEKMSKeyId"] = kms_key_id

        try:
            if extra_args:
                self._client.upload_file(str(source), bucket, key, ExtraArgs=extra_args)
            else:
                self._client.upload_file(str(source), bucket, key)
        except (BotoCoreError, ClientError, OSError) as exc:
            raise S3OperationError("Failed to upload file to S3") from exc

    def download_file(self, bucket: str, key: str, local_path: str) -> None:
        destination = Path(local_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._client.download_file(bucket, key, str(destination))
        except (BotoCoreError, ClientError, OSError) as exc:
            raise S3OperationError("Failed to download file from S3") from exc
