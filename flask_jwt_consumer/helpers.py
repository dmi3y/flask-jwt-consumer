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


# Format error response and append status code
def get_jwt_raw():
    """Obtains the Access Token from the Authorization Header."""
    auth = request.headers.get(config.header_name, None)
    if not auth:
        raise AuthError({'code': 'authorization_header_missing',
                        'description': 'Authorization header is expected.'},
                        401)

    parts = auth.split()

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

    token = parts[1]
    return token


def get_jwt_payload():
    """
    Returns the python dictionary which has all of the data in this JWT.

    If noJWT is currently present, and empty dict is returned
    """
    return getattr(_request_ctx_stack.top, 'jwt_payload', {})
