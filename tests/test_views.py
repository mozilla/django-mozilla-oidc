try:
    from urlparse import parse_qs, urlparse
except ImportError:
    from urllib.parse import parse_qs, urlparse

from mock import patch

from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse
from django.test import RequestFactory, TestCase, override_settings

from mozilla_django_oidc import views


User = get_user_model()


class OIDCAuthorizationCallbackViewTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(LOGIN_REDIRECT_URL='/success')
    def test_post_auth_success(self):
        """Test successful callback request to RP."""

        user = User.objects.create_user('example_username')
        user.is_active = True
        user.save()

        post_data = {
            'code': 'example_code',
            'state': 'example_state'
        }
        url = reverse('oidc_authentication_callback')
        request = self.factory.post(url, post_data)
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch('mozilla_django_oidc.views.auth.authenticate') as mock_auth:
            with patch('mozilla_django_oidc.views.auth.login') as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)

                mock_auth.assert_called_once_with(code='example_code', state='example_state')
                mock_login.assert_called_once_with(request, user)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/success')

    @override_settings(LOGIN_REDIRECT_URL_FAILURE='/failure')
    def test_post_auth_failure_nonexisting_user(self):
        """Test unsuccessful authentication and redirect url."""

        post_data = {
            'code': 'example_code',
            'state': 'example_state'
        }

        url = reverse('oidc_authentication_callback')
        request = self.factory.post(url, post_data)
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch('mozilla_django_oidc.views.auth.authenticate') as mock_auth:
            mock_auth.return_value = None
            response = callback_view(request)

            mock_auth.assert_called_once_with(code='example_code', state='example_state')

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/failure')

    @override_settings(LOGIN_REDIRECT_URL_FAILURE='/failure')
    def test_post_auth_failure_inactive_user(self):
        """Test authentication failure attempt for an inactive user."""

        user = User.objects.create_user('example_username')
        user.is_active = False
        user.save()

        post_data = {
            'code': 'example_code',
            'state': 'example_state'
        }

        url = reverse('oidc_authentication_callback')
        request = self.factory.post(url, post_data)
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch('mozilla_django_oidc.views.auth.authenticate') as mock_auth:
            mock_auth.return_value = user
            response = callback_view(request)

            mock_auth.assert_called_once_with(code='example_code', state='example_state')

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/failure')

    @override_settings(LOGIN_REDIRECT_URL_FAILURE='/failure')
    def test_post_auth_dirty_data(self):
        """Test authentication attempt with wrong post data."""
        post_data = {
            'foo': 'bar',
        }

        url = reverse('oidc_authentication_callback')
        request = self.factory.post(url, post_data)
        callback_view = views.OIDCAuthenticationCallbackView.as_view()
        response = callback_view(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/failure')


class OIDCAuthorizationRequestViewTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='https://server.example.com/auth')
    @override_settings(OIDC_OP_CLIENT_ID='example_id')
    def test_get(self):
        """Test initiation of a successful OIDC attempt."""

        url = reverse('oidc_authorization_init')
        request = self.factory.get(url)
        login_view = views.OIDCAuthenticationRequestView.as_view()
        response = login_view(request)
        self.assertEqual(response.status_code, 302)

        o = urlparse(response.url)
        expected_query = {
            'response_type': ['code'],
            'scope': ['openid'],
            'client_id': ['example_id'],
            'redirect_uri': ['/oidc/authentication_callback/']
        }
        self.assertDictEqual(parse_qs(o.query), expected_query)
        self.assertEqual(o.hostname, 'server.example.com')
        self.assertEqual(o.path, '/auth')
