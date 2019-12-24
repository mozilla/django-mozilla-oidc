========
Settings
========

This document describes the Django settings that can be used to customize the configuration
of ``mozilla-django-oidc``.

.. py:attribute:: OIDC_OP_AUTHORIZATION_ENDPOINT

   :default: No default

   URL of your OpenID Connect provider authorization endpoint.

.. py:attribute:: OIDC_OP_TOKEN_ENDPOINT

   :default: No default

   URL of your OpenID Connect provider token endpoint

.. py:attribute:: OIDC_OP_USER_ENDPOINT

   :default: No default

   URL of your OpenID Connect provider userinfo endpoint

.. py:attribute:: OIDC_RP_CLIENT_ID

   :default: No default

   OpenID Connect client ID provided by your OP

.. py:attribute:: OIDC_RP_CLIENT_SECRET

   :default: No default

   OpenID Connect client secret provided by your OP

.. py:attribute:: OIDC_VERIFY_JWT

   :default: ``True``

   Controls whether the OpenID Connect client verifies the signature of the JWT tokens

.. py:attribute:: OIDC_USE_NONCE

   :default: ``True``

   Controls whether the OpenID Connect client uses nonce verification

.. py:attribute:: OIDC_VERIFY_SSL

   :default: ``True``

   Controls whether the OpenID Connect client verifies the SSL certificate of the OP responses

.. py:attribute:: OIDC_EXEMPT_URLS

   :default: ``[]``

   This is a list of absolute url paths or Django view names. This plus the
   mozilla-django-oidc urls are exempted from the session renewal by the
   ``SessionRefresh`` middleware.

.. py:attribute:: OIDC_CREATE_USER

   :default: ``True``

   Enables or disables automatic user creation during authentication

.. py:attribute:: OIDC_STATE_SIZE

   :default: ``32``

   Sets the length of the random string used for OpenID Connect state verification

.. py:attribute:: OIDC_NONCE_SIZE

   :default: ``32``

   Sets the length of the random string used for OpenID Connect nonce verification

.. py:attribute:: OIDC_REDIRECT_FIELD_NAME

   :default: ``next``

   Sets the GET parameter that is being used to define the redirect URL after succesful authentication

.. py:attribute:: OIDC_CALLBACK_CLASS

   :default: ``mozilla_django_oidc.views.OIDCAuthenticationCallbackView``

   Allows you to substitute a custom class-based view to be used as OpenID Connect
   callback URL.

   .. note::

      When using a custom callback view, it is generally a good idea to subclass the
      default ``OIDCAuthenticationCallbackView`` and override the methods you want to change.

.. py:attribute:: OIDC_AUTHENTICATE_CLASS

   :default: ``mozilla_django_oidc.views.OIDCAuthenticationRequestView``

   Allows you to substitute a custom class-based view to be used as OpenID Connect
   authenticate URL.

   .. note::

      When using a custom authenticate view, it is generally a good idea to subclass the
      default ``OIDCAuthenticationRequestView`` and override the methods you want to change.

.. py:attribute:: OIDC_RP_SCOPES

   :default: ``openid email``

   The OpenID Connect scopes to request during login.

   .. warning::

      When using custom scopes consider overriding the :ref:`claim verification method <advanced_claim_verification>`
      since the default one only works for the default ``mozilla-django-oidc`` configuration.

.. py:attribute:: OIDC_STORE_ACCESS_TOKEN

   :default: ``False``

   Controls whether the OpenID Connect client stores the OIDC ``access_token`` in the user session.
   The session key used to store the data is ``oidc_access_token``.

   By default we want to store as few credentials as possible so this feature defaults to ``False``
   and it's use is discouraged.

   .. warning::
      This feature stores authentication information in the session. If used in combination with Django's
      cookie-based session backend, those tokens will be visible in the browser's cookie store.

.. py:attribute:: OIDC_STORE_ID_TOKEN

   :default: ``False``

   Controls whether the OpenID Connect client stores the OIDC ``id_token`` in the user session.
   The session key used to store the data is ``oidc_id_token``.

.. py:attribute:: OIDC_AUTH_REQUEST_EXTRA_PARAMS

   :default: `{}`

   Additional parameters to include in the initial authorization request.

.. py:attribute:: OIDC_RP_SIGN_ALGO

   :default: ``HS256``

   Sets the algorithm the IdP uses to sign ID tokens.

.. py:attribute:: OIDC_RP_IDP_SIGN_KEY

   :default: ``None``

   Sets the key the IdP uses to sign ID tokens in the case of an RSA sign algorithm.
   Should be the signing key in PEM or DER format.

.. py:attribute:: LOGIN_REDIRECT_URL

   :default: ``/accounts/profile``

   Path to redirect to on successful login. If you don't specify this, the
   default Django value will be used.

   .. seealso::

      https://docs.djangoproject.com/en/1.11/ref/settings/#login-redirect-url

.. py:attribute:: LOGIN_REDIRECT_URL_FAILURE

   :default: ``/``

   Path to redirect to on an unsuccessful login attempt.

.. py:attribute:: LOGOUT_REDIRECT_URL

   :default: ``/`` (Django <= 1.9) ``None`` (Django 1.10+)

   After the logout view has logged the user out, it redirects to this url path.

   .. seealso::

      https://docs.djangoproject.com/en/1.11/ref/settings/#logout-redirect-url

.. py:attribute:: OIDC_OP_LOGOUT_URL_METHOD

   :default: ``''`` (will use ``LOGOUT_REDIRECT_URL``)

   Function path that returns a URL to redirect the user to after
   ``auth.logout()`` is called.

   .. versionchanged:: 0.7.0
      The function must now take a ``request`` parameter.

.. py:attribute:: OIDC_AUTHENTICATION_CALLBACK_URL

   :default: ``oidc_authentication_callback``

   URL pattern name for ``OIDCAuthenticationCallbackView``. Will be passed to ``reverse``.
   The pattern can also include namespace in order to resolve included urls.

   .. seealso::

      https://docs.djangoproject.com/en/2.0/topics/http/urls/#url-namespaces

.. py:attribute:: OIDC_ALLOW_UNSECURED_JWT

   :default: ``False``

   Controls whether the authentication backend is going to allow unsecured JWT tokens (tokens with header ``{"alg":"none"}``).
   This needs to be set to ``True`` if OP is returning unsecured JWT tokens and RP wants to accept them.

   .. seealso::

      https://tools.ietf.org/html/rfc7519#section-6

.. py:attribute:: OIDC_TOKEN_USE_BASIC_AUTH

   :default: False

   Use HTTP Basic Authentication instead of sending the client secret in token request POST body.

.. py:attribute:: OIDC_OP_METADATA_ENDPOINT

   :default: No default

   URL of your OpenID Connect provider metadata endpoint. It will be used to configure other endpoints if  ``OIDC_REQ_METADATA`` option is set to ``True``.

.. py:attribute:: OIDC_REQ_METADATA

   :default: ``False``

   Use OpenID Connect provider metadata endpoint to configure other endpoints.

.. py:attribute:: OIDC_REQ_METADATA_CACHE

   :default: ``default``

   Django cache for caching metadata. By default Django's ``LocMemCache`` is used.

   .. seealso::

      https://docs.djangoproject.com/en/2.2/topics/cache/#local-memory-caching
