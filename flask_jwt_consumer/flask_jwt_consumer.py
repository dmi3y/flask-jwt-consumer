# -*- coding: utf-8 -*-
""" Ensures JWT secure communication."""
# Shamelessly (mostly) stolen from https://auth0.com/docs/quickstart/backend/python
# Inspired by https://github.com/vimalloc/flask-jwt-simple.


from functools import wraps

import jwt
from flask import _request_ctx_stack, current_app, request


# Error handler
class AuthError(Exception):
    """Throws exeptions period."""

    def __init__(self, error, status_code):
        """Initializer period."""
        self.content = error
        self.code = status_code


# Main JWT manager object
class JWTManager(object):
    """
    This object is used to hold the JWT settings and callback functions.

    Instances :class:`JWTManager` are *not* bound to specific apps, so
    you can create one in the main body of your code and then bind it
    to your app in a factory function.
    """

    def __init__(self, app=None):
        """
        Create the JWTManager instance.

        You can either pass a flask application
        in directly here to register this extension with the flask app, or
        call init_app after creating this object
        :param app: A flask application
        """
        # Register this extension with the flask app now (if it is provided)
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Register this extension with the flask app.

        :param app: A flask application
        """
        # Save this so we can use it later in the extension
        if not hasattr(app, 'extensions'):   # pragma: no cover
            app.extensions = {}
        app.extensions['flask-jwt-management'] = self
        self._set_default_configuration_options(app)

    @staticmethod
    def _set_default_configuration_options(app):
        """Sets the default configuration options used by this extension."""
        # Options for JWTs when the TOKEN_LOCATION is headers
        app.config.setdefault('JWT_HEADER_NAME', 'Authorization')
        app.config.setdefault('JWT_HEADER_TYPE', 'Bearer')

        # What algorithm to use to sign the token. See here for a list of options:
        # https://github.com/jpadilla/pyjwt/blob/master/jwt/api_jwt.py
        app.config.setdefault('JWT_ALGORITHM', 'RS256')

        # Expected value of the audience claim
        app.config.setdefault('JWT_IDENTITY', None)

        # Key to verify JWTs with when use when using an asymmetric
        # (public/private key) algorithms, such as RS* or EC*
        app.config.setdefault('JWT_AUTHORIZED_KEYS', None)


class _Config(object):
    """
    Helper object for accessing and verifying options in this extension.

    This is meant for internal use of the application; modifying config options
    should be done with flasks ```app.config```.
    Default values for the configuration options are set in the jwt_manager
    object. All of these values are read only.
    """

    @property
    def decode_keys(self):
        return self._public_keys

    @property
    def header_name(self):
        name = current_app.config['JWT_HEADER_NAME']
        if not name:
            raise RuntimeError('JWT_HEADER_NAME cannot be empty')
        return name

    @property
    def header_type(self):
        return current_app.config['JWT_HEADER_TYPE']

    @property
    def algorithm(self):
        return current_app.config['JWT_ALGORITHM']

    @property
    def audience(self):
        return current_app.config['JWT_IDENTITY']

    @property
    def _public_keys(self):
        keys = current_app.config['JWT_AUTHORIZED_KEYS']
        if not keys:
            raise RuntimeError('JWT_AUTHORIZED_KEYS must be set to use '
                               'asymmetric cryptography algorithm '
                               '"{}"'.format(self.algorithm))
        return bytes(keys, 'utf-8').splitlines()


config = _Config()


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
    return bytes(token, 'utf-8')


def get_jwt_payload():
    """
    Returns the python dictionary which has all of the data in this JWT.

    If noJWT is currently present, and empty dict is returned
    """
    return getattr(_request_ctx_stack.top, 'jwt_payload', {})


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


def requires_jwt(f):
    """Determines if the Access Token is valid."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_jwt_raw()
        key = _brute_force_key(token)
        if key:
            try:
                payload = jwt.decode(
                    token,
                    key,
                    algorithms=config.algorithm,
                    audience=config.audience
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({'code': 'token_expired',
                                'description': 'Token is expired.'},
                                401)
            except (jwt.InvalidAudienceError, jwt.InvalidIssuerError, jwt.InvalidIssuedAtError):
                raise AuthError({'code': 'invalid_claims',
                                'description': 'Incorrect claims, please check the issued at, audience or issuer.'},
                                401)
            except jwt.MissingRequiredClaimError:
                raise AuthError({'code': 'invalid_claims',
                                'description': 'Missing claims, please check the audience.'},
                                401)
            except jwt.PyJWTError:
                raise AuthError({'code': 'invalid_header',
                                'description': 'Unable to parse authentication token.'},
                                401)

            _request_ctx_stack.top.jwt_payload = payload
            return f(*args, **kwargs)
        raise AuthError({'code': 'Invalid_header.',
                        'description': 'Unable to find appropriate key.'},
                        401)
    return decorated
