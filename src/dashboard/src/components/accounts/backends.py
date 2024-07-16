import json

from components.helpers import generate_api_key
from django.conf import settings
from django_auth_ldap.backend import LDAPBackend
from django_cas_ng.backends import CASBackend
from django.core.exceptions import ImproperlyConfigured
from josepy.jws import JWS
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from shibboleth.backends import ShibbolethRemoteUserBackend


class CustomShibbolethRemoteUserBackend(ShibbolethRemoteUserBackend):
    def configure_user(self, user):
        generate_api_key(user)
        return user


class CustomCASBackend(CASBackend):
    def configure_user(self, user):
        generate_api_key(user)
        # If CAS_AUTOCONFIGURE_EMAIL and CAS_EMAIL_DOMAIN settings are
        # configured, add an email address for this user, using rule
        # username@domain.
        if settings.CAS_AUTOCONFIGURE_EMAIL and settings.CAS_EMAIL_DOMAIN:
            user.email = f"{user.username}@{settings.CAS_EMAIL_DOMAIN}"
            user.save()
        return user


class CustomLDAPBackend(LDAPBackend):
    """Append a usernamed suffix to LDAP users, if configured"""

    def ldap_to_django_username(self, username):
        return username.rstrip(settings.AUTH_LDAP_USERNAME_SUFFIX)

    def django_to_ldap_username(self, username):
        return username + settings.AUTH_LDAP_USERNAME_SUFFIX


class CustomOIDCBackend(OIDCAuthenticationBackend):
    """
    Provide OpenID Connect authentication
    """

    #@staticmethod
    #def get_settings(attr, *args):
    #    request = args[0]
    #    provider = request.GET.get(settings.OIDC_PROVIDER_QUERY_PARAM_NAME, settings.OIDC_PRIMARY_PROVIDER_NAME)
    #    setting = settings.OIDC_PROVIDERS.get(provider, {}).get(attr)

    #    if not setting:
    #        raise ImproperlyConfigured(f"Setting {attr} for provider {provider} not found")

    #    return setting

    @staticmethod
    def get_settings(attr, *args):
        # Retrieve the settings directly from the configured settings
        return getattr(settings, attr, None)

    #def authenticate(self, *args, **kwargs):
    #    request = args[0]
    #    provider = request.GET.get(settings.OIDC_PROVIDER_QUERY_PARAM_NAME, settings.OIDC_PRIMARY_PROVIDER_NAME)
    #    client_id =settings.OIDC_PROVIDERS.get(provider, {}).get('OIDC_RP_CLIENT_ID')
    #    client_secret = settings.OIDC_PROVIDERS.get(provider, {}).get('OIDC_RP_CLIENT_SECRET')

    #    setattr(settings, 'OIDC_RP_CLIENT_ID', client_id)
    #    setattr(settings, 'OIDC_RP_CLIENT_SECRET', client_secret)

    #    return super().authenticate(*args, **kwargs)

    def get_userinfo(self, access_token, id_token, verified_id):
        """
        Extract user details from JSON web tokens
        These map to fields on the user field.
        """

        def decode_token(token):
            sig = JWS.from_compact(token.encode("utf-8"))
            payload = sig.payload.decode("utf-8")
            return json.loads(payload)

        access_info = decode_token(access_token)
        id_info = decode_token(id_token)

        info = {}

        for oidc_attr, user_attr in settings.OIDC_ACCESS_ATTRIBUTE_MAP.items():
            if oidc_attr in access_info:
                info.setdefault(user_attr, access_info[oidc_attr])

        for oidc_attr, user_attr in settings.OIDC_ID_ATTRIBUTE_MAP.items():
            if oidc_attr in id_info:
                info.setdefault(user_attr, id_info[oidc_attr])

        return info

    def create_user(self, user_info):
        user = super().create_user(user_info)
        for attr, value in user_info.items():
            setattr(user, attr, value)
        user.save()
        generate_api_key(user)
        return user
