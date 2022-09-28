import jwt
from flask import _request_ctx_stack, current_app, request

from functools import wraps

from .errors import AuthError
from .helpers import get_jwt_raw, _brute_force_key
from .config import config


def requires_jwt(f, **kwparams):
    """Determines if the Access Token is valid."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_jwt_raw(kwparams.get("use_cookie", False))
        key = _brute_force_key(token)
        if key:
            try:
                jwt_config = {
                    'algorithms': config.algorithm
                }
                if config.audience:
                    jwt_config.update({
                        'audience': config.audience
                    })
                if config.verify_aud is False:
                    jwt_config.update({'options': {'verify_aud': False}})
                payload = jwt.decode(
                    token,
                    key,
                    **jwt_config
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
            more = {}
            if kwparams.get('pass_token_payload', False):
                more.update({'token_payload': payload})
            return f(*args, **kwargs, **more)
        raise AuthError({'code': 'Invalid_header.',
                        'description': 'Unable to find appropriate key.'},
                        401)
    return decorated
