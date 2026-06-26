from unittest.mock import MagicMock, patch

from cred import (
    _SERVICE_NAME,
    delete_credential,
    get_credential,
    list_credentials,
    set_credential,
)


class TestGetCredential:
    """Testes para get_credential()."""

    @patch("cred._get_keyring")
    def test_existing_credential(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "secret_value"
        mock_kr.return_value = kr
        assert get_credential("my_token") == "secret_value"
        kr.get_password.assert_called_once_with(_SERVICE_NAME, "my_token")

    @patch("cred._get_keyring")
    def test_missing_credential(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = None
        mock_kr.return_value = kr
        assert get_credential("nonexistent") is None

    @patch("cred._get_keyring")
    def test_keyring_unavailable(self, mock_kr):
        mock_kr.return_value = None
        assert get_credential("my_token") is None


class TestSetCredential:
    """Testes para set_credential()."""

    @patch("cred._get_keyring")
    @patch("cred._update_registry")
    def test_set_with_value(self, mock_reg, mock_kr):
        kr = MagicMock()
        mock_kr.return_value = kr
        assert set_credential("my_token", "abc123") is True
        kr.set_password.assert_called_once_with(_SERVICE_NAME, "my_token", "abc123")
        mock_reg.assert_called_once_with("my_token", add=True)

    @patch("cred._get_keyring")
    def test_set_empty_value(self, mock_kr):
        mock_kr.return_value = MagicMock()
        assert set_credential("my_token", "") is False

    @patch("cred._get_keyring")
    def test_keyring_unavailable(self, mock_kr):
        mock_kr.return_value = None
        assert set_credential("my_token", "abc") is False


class TestDeleteCredential:
    """Testes para delete_credential()."""

    @patch("cred._get_keyring")
    @patch("cred._update_registry")
    def test_delete_existing(self, mock_reg, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "old_value"
        mock_kr.return_value = kr
        assert delete_credential("my_token") is True
        kr.delete_password.assert_called_once_with(_SERVICE_NAME, "my_token")
        mock_reg.assert_called_once_with("my_token", add=False)

    @patch("cred._get_keyring")
    def test_delete_nonexistent(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = None
        mock_kr.return_value = kr
        assert delete_credential("nonexistent") is False

    @patch("cred._get_keyring")
    def test_keyring_unavailable(self, mock_kr):
        mock_kr.return_value = None
        assert delete_credential("my_token") is False


class TestListCredentials:
    """Testes para list_credentials()."""

    @patch("cred._list_credentials")
    def test_list_with_creds(self, mock_list):
        mock_list.return_value = ["bearer_token", "nvd_key"]
        result = list_credentials()
        assert result == ["bearer_token", "nvd_key"]

    @patch("cred._list_credentials")
    def test_list_empty(self, mock_list):
        mock_list.return_value = []
        result = list_credentials()
        assert result == []


class TestRegistry:
    """Testes para _update_registry()."""

    @patch("cred._get_keyring")
    def test_add_to_registry(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = None
        mock_kr.return_value = kr
        from cred import _update_registry

        _update_registry("new_cred", add=True)
        kr.set_password.assert_called_once_with(
            _SERVICE_NAME, "__registry__", "new_cred"
        )

    @patch("cred._get_keyring")
    def test_add_to_existing_registry(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "token_a"
        mock_kr.return_value = kr
        from cred import _update_registry

        _update_registry("token_b", add=True)
        kr.set_password.assert_called_once_with(
            _SERVICE_NAME, "__registry__", "token_a\ntoken_b"
        )

    @patch("cred._get_keyring")
    def test_remove_from_registry(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "token_a\ntoken_b"
        mock_kr.return_value = kr
        from cred import _update_registry

        _update_registry("token_a", add=False)
        kr.set_password.assert_called_once_with(
            _SERVICE_NAME, "__registry__", "token_b"
        )
