"""Tests for SQSChangeProvider and PubSubChangeProvider (Phase L)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from urllib.parse import quote_plus

import pytest


class TestSQSChangeProvider:
    def test_init(self):
        from openlabels.core.change_providers import SQSChangeProvider

        provider = SQSChangeProvider(
            queue_url="https://sqs.us-east-1.amazonaws.com/123456/my-queue",
            bucket="my-bucket",
        )
        assert provider._queue_url == "https://sqs.us-east-1.amazonaws.com/123456/my-queue"
        assert provider._bucket == "my-bucket"
        assert provider._max_messages == 10
        assert provider._wait_time_seconds == 5

    @pytest.mark.asyncio
    async def test_changed_files_object_created(self):
        from openlabels.core.change_providers import SQSChangeProvider

        provider = SQSChangeProvider(
            queue_url="https://sqs.example.com/queue",
            bucket="test-bucket",
        )

        mock_client = MagicMock()
        mock_client.receive_message.return_value = {
            "Messages": [
                {
                    "ReceiptHandle": "handle-1",
                    "Body": json.dumps({
                        "Records": [
                            {
                                "eventName": "ObjectCreated:Put",
                                "s3": {
                                    "object": {
                                        "key": "data/report.pdf",
                                        "size": 2048,
                                        "eTag": "abc123",
                                    }
                                },
                            }
                        ]
                    }),
                }
            ]
        }
        mock_client.delete_message_batch.return_value = {}
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].path == "s3://test-bucket/data/report.pdf"
        assert files[0].name == "report.pdf"
        assert files[0].size == 2048
        assert files[0].change_type == "created"
        assert files[0].adapter == "s3"
        assert files[0].item_id == "data/report.pdf"
        assert files[0].permissions["etag"] == "abc123"

    @pytest.mark.asyncio
    async def test_changed_files_object_removed(self):
        from openlabels.core.change_providers import SQSChangeProvider

        provider = SQSChangeProvider(
            queue_url="https://sqs.example.com/queue",
            bucket="test-bucket",
        )

        mock_client = MagicMock()
        mock_client.receive_message.return_value = {
            "Messages": [
                {
                    "ReceiptHandle": "handle-1",
                    "Body": json.dumps({
                        "Records": [
                            {
                                "eventName": "ObjectRemoved:Delete",
                                "s3": {"object": {"key": "old-file.txt", "size": 0}},
                            }
                        ]
                    }),
                }
            ]
        }
        mock_client.delete_message_batch.return_value = {}
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].change_type == "deleted"

    @pytest.mark.asyncio
    async def test_changed_files_url_decodes_key(self):
        from openlabels.core.change_providers import SQSChangeProvider

        provider = SQSChangeProvider(
            queue_url="https://sqs.example.com/queue",
            bucket="test-bucket",
        )

        encoded_key = quote_plus("path/my file (1).txt")
        mock_client = MagicMock()
        mock_client.receive_message.return_value = {
            "Messages": [
                {
                    "ReceiptHandle": "handle-1",
                    "Body": json.dumps({
                        "Records": [
                            {
                                "eventName": "ObjectCreated:Put",
                                "s3": {"object": {"key": encoded_key, "size": 100}},
                            }
                        ]
                    }),
                }
            ]
        }
        mock_client.delete_message_batch.return_value = {}
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert files[0].item_id == "path/my file (1).txt"

    @pytest.mark.asyncio
    async def test_changed_files_sns_wrapped(self):
        from openlabels.core.change_providers import SQSChangeProvider

        provider = SQSChangeProvider(
            queue_url="https://sqs.example.com/queue",
            bucket="test-bucket",
        )

        inner_body = json.dumps({
            "Records": [
                {
                    "eventName": "ObjectCreated:Put",
                    "s3": {"object": {"key": "via-sns.txt", "size": 50}},
                }
            ]
        })

        mock_client = MagicMock()
        mock_client.receive_message.return_value = {
            "Messages": [
                {
                    "ReceiptHandle": "handle-1",
                    "Body": json.dumps({
                        "TopicArn": "arn:aws:sns:us-east-1:123456:my-topic",
                        "Message": inner_body,
                    }),
                }
            ]
        }
        mock_client.delete_message_batch.return_value = {}
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].item_id == "via-sns.txt"

    @pytest.mark.asyncio
    async def test_changed_files_empty_queue(self):
        from openlabels.core.change_providers import SQSChangeProvider

        provider = SQSChangeProvider(
            queue_url="https://sqs.example.com/queue",
            bucket="test-bucket",
        )

        mock_client = MagicMock()
        mock_client.receive_message.return_value = {}
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 0

    @pytest.mark.asyncio
    async def test_deletes_messages_after_processing(self):
        from openlabels.core.change_providers import SQSChangeProvider

        provider = SQSChangeProvider(
            queue_url="https://sqs.example.com/queue",
            bucket="test-bucket",
        )

        mock_client = MagicMock()
        mock_client.receive_message.return_value = {
            "Messages": [
                {
                    "ReceiptHandle": "rh-1",
                    "Body": json.dumps({
                        "Records": [{"eventName": "ObjectCreated:Put", "s3": {"object": {"key": "a.txt", "size": 1}}}]
                    }),
                },
                {
                    "ReceiptHandle": "rh-2",
                    "Body": json.dumps({
                        "Records": [{"eventName": "ObjectCreated:Put", "s3": {"object": {"key": "b.txt", "size": 2}}}]
                    }),
                },
            ]
        }
        mock_client.delete_message_batch.return_value = {}
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        mock_client.delete_message_batch.assert_called_once()
        call_kwargs = mock_client.delete_message_batch.call_args
        entries = call_kwargs[1]["Entries"] if "Entries" in (call_kwargs[1] or {}) else call_kwargs[0][0] if call_kwargs[0] else []
        # Verify via lambda call
        assert mock_client.delete_message_batch.called


class TestPubSubChangeProvider:
    def test_init(self):
        from openlabels.core.change_providers import PubSubChangeProvider

        provider = PubSubChangeProvider(
            project="my-project",
            subscription="my-sub",
            bucket="my-bucket",
        )
        assert provider._project == "my-project"
        assert provider._subscription == "my-sub"
        assert provider._bucket == "my-bucket"
        assert provider._max_messages == 100

    @pytest.mark.asyncio
    async def test_changed_files_object_finalize(self):
        from openlabels.core.change_providers import PubSubChangeProvider

        provider = PubSubChangeProvider(
            project="my-project",
            subscription="my-sub",
            bucket="my-bucket",
        )

        mock_msg = MagicMock()
        mock_msg.ack_id = "ack-1"
        mock_msg.message.attributes = {
            "eventType": "OBJECT_FINALIZE",
            "objectId": "uploads/data.csv",
            "bucketId": "my-bucket",
            "objectSize": "512",
            "objectGeneration": "3001",
        }
        mock_msg.message.data = b""

        mock_response = MagicMock()
        mock_response.received_messages = [mock_msg]

        mock_client = MagicMock()
        mock_client.subscription_path.return_value = (
            "projects/my-project/subscriptions/my-sub"
        )
        mock_client.pull.return_value = mock_response
        mock_client.acknowledge.return_value = None
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].path == "gs://my-bucket/uploads/data.csv"
        assert files[0].name == "data.csv"
        assert files[0].size == 512
        assert files[0].change_type == "created"
        assert files[0].adapter == "gcs"
        assert files[0].item_id == "uploads/data.csv"
        assert files[0].permissions["generation"] == 3001

    @pytest.mark.asyncio
    async def test_changed_files_object_delete(self):
        from openlabels.core.change_providers import PubSubChangeProvider

        provider = PubSubChangeProvider(
            project="my-project",
            subscription="my-sub",
            bucket="my-bucket",
        )

        mock_msg = MagicMock()
        mock_msg.ack_id = "ack-1"
        mock_msg.message.attributes = {
            "eventType": "OBJECT_DELETE",
            "objectId": "old-file.txt",
            "bucketId": "my-bucket",
        }
        mock_msg.message.data = b""

        mock_response = MagicMock()
        mock_response.received_messages = [mock_msg]

        mock_client = MagicMock()
        mock_client.subscription_path.return_value = "projects/p/subscriptions/s"
        mock_client.pull.return_value = mock_response
        mock_client.acknowledge.return_value = None
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].change_type == "deleted"

    @pytest.mark.asyncio
    async def test_changed_files_json_body_fallback(self):
        from openlabels.core.change_providers import PubSubChangeProvider

        provider = PubSubChangeProvider(
            project="my-project",
            subscription="my-sub",
            bucket="my-bucket",
        )

        mock_msg = MagicMock()
        mock_msg.ack_id = "ack-1"
        mock_msg.message.attributes = {
            "eventType": "OBJECT_FINALIZE",
        }
        mock_msg.message.data = json.dumps({
            "name": "from-body.txt",
            "bucket": "my-bucket",
        }).encode("utf-8")

        mock_response = MagicMock()
        mock_response.received_messages = [mock_msg]

        mock_client = MagicMock()
        mock_client.subscription_path.return_value = "projects/p/subscriptions/s"
        mock_client.pull.return_value = mock_response
        mock_client.acknowledge.return_value = None
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].item_id == "from-body.txt"

    @pytest.mark.asyncio
    async def test_changed_files_empty_response(self):
        from openlabels.core.change_providers import PubSubChangeProvider

        provider = PubSubChangeProvider(
            project="my-project",
            subscription="my-sub",
            bucket="my-bucket",
        )

        mock_response = MagicMock()
        mock_response.received_messages = []

        mock_client = MagicMock()
        mock_client.subscription_path.return_value = "projects/p/subscriptions/s"
        mock_client.pull.return_value = mock_response
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 0

    @pytest.mark.asyncio
    async def test_acknowledges_messages_after_processing(self):
        from openlabels.core.change_providers import PubSubChangeProvider

        provider = PubSubChangeProvider(
            project="my-project",
            subscription="my-sub",
            bucket="my-bucket",
        )

        mock_msg = MagicMock()
        mock_msg.ack_id = "ack-42"
        mock_msg.message.attributes = {
            "eventType": "OBJECT_FINALIZE",
            "objectId": "file.txt",
            "bucketId": "my-bucket",
        }
        mock_msg.message.data = b""

        mock_response = MagicMock()
        mock_response.received_messages = [mock_msg]

        mock_client = MagicMock()
        mock_client.subscription_path.return_value = "projects/p/subscriptions/s"
        mock_client.pull.return_value = mock_response
        mock_client.acknowledge.return_value = None
        provider._client = mock_client

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        mock_client.acknowledge.assert_called_once()
