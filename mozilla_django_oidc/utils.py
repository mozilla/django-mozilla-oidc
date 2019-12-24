import requests
from django.core.cache import caches

from mozilla_django_oidc.constants import OPMetadataKey, OIDCCacheKey

try:
    from urllib.request import parse_http_list, parse_keqv_list
except ImportError:
    # python < 3
    from urllib2 import parse_http_list, parse_keqv_list
from django import VERSION
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def parse_www_authenticate_header(header):
    """
    Convert a WWW-Authentication header into a dict that can be used
    in a JSON response.
    """
    items = parse_http_list(header)
    return parse_keqv_list(items)


def import_from_settings(attr, *args):
    """
    Load an attribute from the django settings.

    :raises:
        ImproperlyConfigured
    """
    try:
        if args:
            return getattr(settings, attr, args[0])
        return getattr(settings, attr)
    except AttributeError:
        raise ImproperlyConfigured('Setting {0} not found'.format(attr))


def absolutify(request, path):
    """Return the absolute URL of a path."""
    return request.build_absolute_uri(path)


# Computed once, reused in every request
_less_than_django_1_10 = VERSION < (1, 10)
# Settings which can be extracted from OpenID provider's metadata.
_op_metadata_settings = [
    'OIDC_OP_TOKEN_ENDPOINT', 'OIDC_OP_USER_ENDPOINT', 'OIDC_OP_JWKS_ENDPOINT',
    'OIDC_OP_AUTHORIZATION_ENDPOINT']


def is_authenticated(user):
    """return True if the user is authenticated.

    This is necessary because in Django 1.10 the `user.is_authenticated`
    stopped being a method and is now a property.
    Actually `user.is_authenticated()` actually works, thanks to a backwards
    compat trick in Django. But in Django 2.0 it will cease to work
    as a callable method.
    """
    if _less_than_django_1_10:
        return user.is_authenticated()
    return user.is_authenticated


def get_op_metadata(op_metadata_endpoint):
    """Return metadata from the metadata endpoint of the OpenID provider"""
    op_metadata = requests.get(
        url=op_metadata_endpoint,
        verify=import_from_settings('OIDC_VERIFY_SSL', True)
    )
    op_metadata.raise_for_status()
    return op_metadata.json()


def is_obtainable_from_op_metadata(attr):
    """Check if the setting can be obtained from OpenID provider's metadata"""
    return attr in _op_metadata_settings


def extract_settings_from_op_metadata(op_metadata, attr):
    """Extract the setting from the OpenId provider's metadata."""
    try:
        if attr == 'OIDC_OP_TOKEN_ENDPOINT':
            return op_metadata[OPMetadataKey.TOKEN_ENDPOINT.value]
        elif attr == 'OIDC_OP_USER_ENDPOINT':
            return op_metadata[OPMetadataKey.USER_INFO_ENDPOINT.value]
        elif attr == 'OIDC_OP_JWKS_ENDPOINT':
            return op_metadata[OPMetadataKey.JWKS_ENDPOINT.value]
        elif attr == 'OIDC_OP_AUTHORIZATION_ENDPOINT':
            return op_metadata[OPMetadataKey.AUTHORIZATION_ENDPOINT.value]

    except KeyError:
        raise KeyError("Attribute: {} is not found in the metadata".format(attr))

    raise ImproperlyConfigured("Attribute: {} is not configured to "
                               "be extracted from metadata".format(attr))


def get_from_op_metadata(attr):
    """Get settings from OpenId provider's metadata and cache it if not already."""
    # By default the 'default' cache is used to cache the metadata.
    cache = caches[import_from_settings("OIDC_REQ_METADATA_CACHE", "default")]
    cached_metadata = cache.get(OIDCCacheKey.OP_METADATA.value)

    if cached_metadata:
        return extract_settings_from_op_metadata(cached_metadata, attr)

    op_metadata = get_op_metadata(import_from_settings("OIDC_OP_METADATA_ENDPOINT"))
    # Cache the results.
    cache.set(OIDCCacheKey.OP_METADATA.value, op_metadata)
    return extract_settings_from_op_metadata(op_metadata, attr)
