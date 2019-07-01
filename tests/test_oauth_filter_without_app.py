import unittest
from unittest.mock import MagicMock, patch

from oauth2_lib.oauth_filter import OAuthFilter


class TestOauthFilterWithoutApp(unittest.TestCase):
    @patch("oauth2_lib.oauth_filter.flask.current_app")
    def test_get_current_user(self, current_app):
        current_app.cache = MagicMock()
        res = OAuthFilter.current_user()
        self.assertEqual(None, res)
