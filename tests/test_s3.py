from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError

from hybrid_crypto_project.core.storage.s3_client import S3OperationError, S3StorageClient


def test_upload_s3_success(tmp_path: Path) -> None:
    source = tmp_path / "bundle.enc"
    source.write_bytes(b"cipher")
    mock_client = Mock()

    with patch(
        "hybrid_crypto_project.core.storage.s3_client.boto3.client",
        return_value=mock_client,
    ):
        client = S3StorageClient(region_name="eu-central-1")
        client.upload_file(str(source), "bucket", "object.enc")

    mock_client.upload_file.assert_called_once()


def test_download_s3_success(tmp_path: Path) -> None:
    destination = tmp_path / "downloaded.enc"
    mock_client = Mock()

    with patch(
        "hybrid_crypto_project.core.storage.s3_client.boto3.client",
        return_value=mock_client,
    ):
        client = S3StorageClient(region_name="eu-central-1")
        client.download_file("bucket", "object.enc", str(destination))

    mock_client.download_file.assert_called_once()


def test_upload_s3_network_error(tmp_path: Path) -> None:
    source = tmp_path / "bundle.enc"
    source.write_bytes(b"cipher")
    mock_client = Mock()
    mock_client.upload_file.side_effect = ClientError(
        {"Error": {"Code": "500", "Message": "internal"}},
        "UploadFile",
    )

    with patch(
        "hybrid_crypto_project.core.storage.s3_client.boto3.client",
        return_value=mock_client,
    ):
        client = S3StorageClient(region_name="eu-central-1")
        with pytest.raises(S3OperationError):
            client.upload_file(str(source), "bucket", "object.enc")
