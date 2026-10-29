import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from aggrec.settings import HttpSettings, Settings


def test_settings_loaded():
    with patch.dict(os.environ, {"AGGREC_CONFIG": "tests/test.toml"}):
        settings = Settings()
    assert settings is not None
    assert settings.clients_database == "test/clients"


def test_settings_default():
    settings = Settings()
    assert settings.http.signature_algorithms == ["ed25519", "ecdsa-p256-sha256", "rsa-v1_5-sha256"]


def test_settings_algorithm():
    settings = Settings(http=HttpSettings(signature_algorithms=["ed25519"]))
    assert settings.http.signature_algorithms == ["ed25519"]


def test_settings_algorithm_invalid():
    with pytest.raises(ValidationError):
        HttpSettings(signature_algorithms=["b0rken"])
    with pytest.raises(ValidationError):
        HttpSettings(default_signature_algorithm=["b0rken"])


def test_settings_algorithm_mismatch():
    with pytest.raises(ValidationError):
        HttpSettings(signature_algorithms=["ed25519"], default_signature_algorithm="ecdsa-p256-sha256")
