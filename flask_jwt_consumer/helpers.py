import jwt
from flask import _request_ctx_stack, request

from .config import config
from .errors import AuthError

def _brute_force_key(token):
    """Looping through all the available keys to find one which is good."""
    valid_key = None
    for key in config.decode_keys:
        try:
            jwt.decode(
                token,
                key,
                algorithms=[config.algorithm],
                options={
                    'verify_signature': True,
                    'verify_exp': False,
                    'verify_nbf': False,
                    'verify_iat': False,
                    'verify_aud': False,
                    'verify_iss': False,
                    'require_exp': False,
                    'require_iat': False,
                    'require_nbf': False
                }
            )
            valid_key = key
        except jwt.PyJWTError:
            pass

        if valid_key:
            break

    return valid_key

#
# NOTE(ian) 09/28/2022:
# We want to support both cookie-auth and header-auth, that can be used flexibily in an app.
# We preferentially look for cookie auth first, and if none can be found then we check the
# header. If the auth is invalid for some reason, or if no auth is found, we raise an error.
#
def get_jwt_raw():
    auth_cookie = request.cookies.get(config.cookie_name, None)
    auth_header = request.headers.get(config.header_name, None)

    if auth_cookie:
        if len(auth_cookie.split()) != 1:
            raise AuthError({'code': 'invalid_cookie',
                            'description': f"Bad cookie {config.cookie_name} . Expected value '<JWT>'"},
                            401)
        return auth_cookie

    if auth_header:
        parts = auth_header.split()
        if parts[0] != config.header_type:
            raise AuthError({'code': 'invalid_header',
                            'description': 'Authorization header must start with {}.'.format(config.header_type)},
                            401)
        elif len(parts) == 1:
            raise AuthError({'code': 'invalid_header',
                            'description': 'Token not found.'},
                            401)
        elif len(parts) > 2:
            raise AuthError({'code': 'invalid_header',
                            'description': 'Authorization header must be {} token.'.format(config.header_type)},
                            401)
        return parts[1]

    raise AuthError({'code': 'no_authorization_error',
                     'description': 'Authorization is required on either the cookie or the header.'},
                        401)


def get_jwt_payload():
    """
    Returns the python dictionary which has all of the data in this JWT.

    If no JWT is currently present, and empty dict is returned
    """
    return getattr(_request_ctx_stack.top, 'jwt_payload', {})
