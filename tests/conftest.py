# conftest.py

"""Shared pytest fixtures for lazy-beanstalk tests."""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock


@pytest.fixture
def mock_boto3_session(monkeypatch):
    """Mock boto3 session for testing."""
    mock_session = Mock()
    mock_session.region_name = "us-west-2"
    return mock_session


@pytest.fixture
def mock_aws_clients():
    """Mock AWS clients for testing."""
    clients = {
        "elasticbeanstalk": Mock(),
        "iam": Mock(),
        "s3": Mock(),
        "elbv2": Mock(),
        "acm": Mock(),
        "route53": Mock(),
        "ec2": Mock(),
        "sts": Mock(),
    }
    return clients


@pytest.fixture
def sample_state():
    """Sample state file content."""
    return {
        "app_name": "test-app",
        "environment_name": "test-app-env",
        "region": "us-west-2",
        "instance_type": "t4g.nano",
        "spot_instances": False,
        "min_instances": 1,
        "max_instances": 1,
        "platform": "64bit Amazon Linux 2023 v4.0.0 running Docker",
        "last_deployed": "2025-10-16T00:00:00Z",
    }


@pytest.fixture
def temp_state_file(tmp_path, sample_state):
    """Create a temporary state file."""
    state_file = tmp_path / ".lazy-beanstalk.state"
    state_file.write_text(json.dumps(sample_state, indent=2))
    return state_file


@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return {
        "app_name": "test-app",
        "environment_name": "test-app-env",
        "region": "us-west-2",
        "instance_type": "t4g.nano",
        "spot_instances": False,
        "min_instances": 1,
        "max_instances": 1,
        "env_vars": {},
        "tags": {"Environment": "development", "ManagedBy": "lazy-beanstalk"},
        "dockerfile_path": "./Dockerfile",
    }
