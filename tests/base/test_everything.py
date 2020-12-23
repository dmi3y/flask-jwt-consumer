"""Testing flask jwt manager."""
from datetime import datetime, timedelta
from unittest import mock
from unittest.mock import PropertyMock

import jwt
import pytest

from flask_jwt_consumer import (AuthError, JWTConsumer, get_jwt_payload,
                                get_jwt_raw, requires_jwt)
from flask_jwt_consumer.helpers import _brute_force_key

JWT_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""
JWT_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwuN+aHSCA+WElMpVwWva
k/WJWxp7IFnQBbihzH1Of/vYcIuwWRQiPlt7gnjdyEiG37UCTNUkRG2hiEEAGMpQ
TNwLUppipnQg8jX59Y23Ey8yMiblTFEac14WvRSwF60fbBf/3NWAjO0C2wQmgzxi
1aNrSok6ow0iw3h99OyVt4yJVWeUKlBAx9BFGsfRDwFVH0ttjdzC6Afkq+pahMbE
cr1XRbN1UB4QWFNflCImwpbvfC4mtZlu+Omi6WWlOVpFZzycf0Eu9+WsHpwoqvVw
OUOiyNSs3WWXHqzl0KexRaT6aAtdm7EYHBr7LE/XJsSqCLWHNuY2IMG76i5aySeC
yPOE5LN9wQgxS1+g44FZunulNrItsoxRFbSZmsv/nNhg3MvMl0qPL9yTVQkE/bb8
tz9VVpcZa1QOKexumam9hUs4QgkVtME18UYbioQzWlzjVgw7NNS01L0wV1DQ7msH
NT/E5SCVXUIEXfjeo60ltd5MkR7IreWlS96SwKHUKqRdN8j9vo9q86jiRm3q3kAe
oVCYQQ9j+L3pytHyilnU+RDYfhpnSWCshvi0RlPh6ul+NftWGMsIaXnE54bNA5YY
fDJI1kHWoHiGzWhyB5AoPdR1ybCaH95e1tRSd+frgRF6e04RpNxbuOT7nT8ZFyyP
y328FIj+KVXAfAziMqx+pt0CAwEAAQ==
-----END PUBLIC KEY-----"""
JWT_ALGORITHM = 'RS256'
RANDOM_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqeiRuTHtA7GgG/N2QXsgkFxj+
pA/6fuiJUHwSu+dBfGy/8riBiL4EnLoFIdJ+g5yXapsGZLSPiwWk432PdX3BBgxa
j3SScYAqMTsftLEZGzQosmr+aJjvBOr309zP+sJDt8ueW/8eapbka1vV4VcqHHDW
qUvtxQtYOfxmz87FlwIDAQAB
-----END PUBLIC KEY-----"""
AUDIENCE = 'self-identity'

AUTHORIZE_KEYS = [
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDC435odIID5YSUylXBa9qT9YlbGnsgWdAFuKHMfU5/+9hwi7BZFCI+W3uCeN3ISIbftQJM1SREbaGIQQAYylBM3AtSmmKmdCDyNfn1jbcTLzIyJuVMURpzXha9FLAXrR9sF//c1YCM7QLbBCaDPGLVo2tKiTqjDSLDeH307JW3jIlVZ5QqUEDH0EUax9EPAVUfS22N3MLoB+Sr6lqExsRyvVdFs3VQHhBYU1+UIibClu98Lia1mW746aLpZaU5WkVnPJx/QS735awenCiq9XA5Q6LI1KzdZZcerOXQp7FFpPpoC12bsRgcGvssT9cmxKoItYc25jYgwbvqLlrJJ4LI84Tks33BCDFLX6DjgVm6e6U2si2yjFEVtJmay/+c2GDcy8yXSo8v3JNVCQT9tvy3P1VWlxlrVA4p7G6Zqb2FSzhCCRW0wTXxRhuKhDNaXONWDDs01LTUvTBXUNDuawc1P8TlIJVdQgRd+N6jrSW13kyRHsit5aVL3pLAodQqpF03yP2+j2rzqOJGbereQB6hUJhBD2P4venK0fKKWdT5ENh+GmdJYKyG+LRGU+Hq6X41+1YYywhpecTnhs0Dlhh8MkjWQdageIbNaHIHkCg91HXJsJof3l7W1FJ35+uBEXp7ThGk3Fu45PudPxkXLI/LfbwUiP4pVcB8DOIyrHBADK==',  # noqa E501
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDC435odIID5YSUylXBa9qT9YlbGnsgWdAFuKHMfU5/+9hwi7BZFCI+W3uCeN3ISIbftQJM1SREbaGIQQAYylBM3AtSmmKmdCDyNfn1jbcTLzIyJuVMURpzXha9FLAXrR9sF//c1YCM7QLbBCaDPGLVo2tKiTqjDSLDeH307JW3jIlVZ5QqUEDH0EUax9EPAVUfS22N3MLoB+Sr6lqExsRyvVdFs3VQHhBYU1+UIibClu98Lia1mW746aLpZaU5WkVnPJx/QS735awenCiq9XA5Q6LI1KzdZZcerOXQp7FFpPpoC12bsRgcGvssT9cmxKoItYc25jYgwbvqLlrJJ4LI84Tks33BCDFLX6DjgVm6e6U2si2yjFEVtJmay/+c2GDcy8yXSo8v3JNVCQT9tvy3P1VWlxlrVA4p7G6Zqb2FSzhCCRW0wTXxRhuKhDNaXONWDDs01LTUvTBXUNDuawc1P8TlIJVdQgRd+N6jrSW13kyRHsit5aVL3pLAodQqpF03yP2+j2rzqOJGbereQB6hUJhBD2P4venK0fKKWdT5ENh+GmdJYKyG+LRGU+Hq6X41+1YYywhpecTnhs0Dlhh8MkjWQdageIbNaHIHkCg91HXJsJof3l7W1FJ35+uBEXp7ThGk3Fu45PudPxkXLI/LfbwUiP4pVcB8DOIyrH6m3Q==',  # noqa E501
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDC435odIID5YSUylXBa9qT9YlbGnsgWdAFuKHMfU5/+9hwi7BZFCI+W3uCeN3ISIbftQJM1SREbaGIQQAYylBM3AtSmmKmdCDyNfn1jbcTLzIyJuVMURpzXha9FLAXrR9sF//c1YCM7QLbBCaDPGLVo2tKiTqjDSLDeH307JW3jIlVZ5QqUEDH0EUax9EPAVUfS22N3MLoB+Sr6lqExsRyvVdFs3VQHhBYU1+UIibClu98Lia1mW746aLpZaU5WkVnPJx/QS735awenCiq9XA5Q6LI1KzdZZcerOXQp7FFpPpoC12bsRgcGvssT9cmxKoItYc25jYgwbvqLlrJJ4LI84Tks33BCDFLX6DjgVm6e6U2si2yjFEVtJmay/+c2GDcy8yXSo8v3JNVCQT9tvy3P1VWlxlrVA4p7G6Zqb2FSzhCCRW0wTXxRhuKhDNaXONWDDs01LTUvTBXUNDuawc1P8TlIJVdQgRd+N6jrSW13kyRHsit5aVL3pLAodQqpF03yP2+j2rzqOJGbereQB6hUJhBD2P4venK0fKKWdT5ENh+GmdJYKyG+LRGU+Hq6X41+1YYywhpecTnhs0Dlhh8MkjWQdageIbNaHIHkCg91HXJsJof3l7W1FJ35+uBEXp7ThGk3Fu45PudPxkXLI/LfbwUiP4pVcB8DOIyrHBADP=='   # noqa E501
]

AUTHORIZE_BAD_KEYS = [
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDC435odIID5YSUylXBa9qT9YlbGnsgWdAFuKHMfU5/+9hwi7BZFCI+W3uCeN3ISIbftQJM1SREbaGIQQAYylBM3AtSmmKmdCDyNfn1jbcTLzIyJuVMURpzXha9FLAXrR9sF//c1YCM7QLbBCaDPGLVo2tKiTqjDSLDeH307JW3jIlVZ5QqUEDH0EUax9EPAVUfS22N3MLoB+Sr6lqExsRyvVdFs3VQHhBYU1+UIibClu98Lia1mW746aLpZaU5WkVnPJx/QS735awenCiq9XA5Q6LI1KzdZZcerOXQp7FFpPpoC12bsRgcGvssT9cmxKoItYc25jYgwbvqLlrJJ4LI84Tks33BCDFLX6DjgVm6e6U2si2yjFEVtJmay/+c2GDcy8yXSo8v3JNVCQT9tvy3P1VWlxlrVA4p7G6Zqb2FSzhCCRW0wTXxRhuKhDNaXONWDDs01LTUvTBXUNDuawc1P8TlIJVdQgRd+N6jrSW13kyRHsit5aVL3pLAodQqpF03yP2+j2rzqOJGbereQB6hUJhBD2P4venK0fKKWdT5ENh+GmdJYKyG+LRGU+Hq6X41+1YYywhpecTnhs0Dlhh8MkjWQdageIbNaHIHkCg91HXJsJof3l7W1FJ35+uBEXp7ThGk3Fu45PudPxkXLI/LfbwUiP4pVcB8DOIyrHBADK==',  # noqa E501
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDC435odIID5YSUylXBa9qT9YlbGnsgWdAFuKHMfU5/+9hwi7BZFCI+W3uCeN3ISIbftQJM1SREbaGIQQAYylBM3AtSmmKmdCDyNfn1jbcTLzIyJuVMURpzXha9FLAXrR9sF//c1YCM7QLbBCaDPGLVo2tKiTqjDSLDeH307JW3jIlVZ5QqUEDH0EUax9EPAVUfS22N3MLoB+Sr6lqExsRyvVdFs3VQHhBYU1+UIibClu98Lia1mW746aLpZaU5WkVnPJx/QS735awenCiq9XA5Q6LI1KzdZZcerOXQp7FFpPpoC12bsRgcGvssT9cmxKoItYc25jYgwbvqLlrJJ4LI84Tks33BCDFLX6DjgVm6e6U2si2yjFEVtJmay/+c2GDcy8yXSo8v3JNVCQT9tvy3P1VWlxlrVA4p7G6Zqb2FSzhCCRW0wTXxRhuKhDNaXONWDDs01LTUvTBXUNDuawc1P8TlIJVdQgRd+N6jrSW13kyRHsit5aVL3pLAodQqpF03yP2+j2rzqOJGbereQB6hUJhBD2P4venK0fKKWdT5ENh+GmdJYKyG+LRGU+Hq6X41+1YYywhpecTnhs0Dlhh8MkjWQdageIbNaHIHkCg91HXJsJof3l7W1FJ35+uBEXp7ThGk3Fu45PudPxkXLI/LfbwUiP4pVcB8DOIyrHbAdQ==',  # noqa E501
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDC435odIID5YSUylXBa9qT9YlbGnsgWdAFuKHMfU5/+9hwi7BZFCI+W3uCeN3ISIbftQJM1SREbaGIQQAYylBM3AtSmmKmdCDyNfn1jbcTLzIyJuVMURpzXha9FLAXrR9sF//c1YCM7QLbBCaDPGLVo2tKiTqjDSLDeH307JW3jIlVZ5QqUEDH0EUax9EPAVUfS22N3MLoB+Sr6lqExsRyvVdFs3VQHhBYU1+UIibClu98Lia1mW746aLpZaU5WkVnPJx/QS735awenCiq9XA5Q6LI1KzdZZcerOXQp7FFpPpoC12bsRgcGvssT9cmxKoItYc25jYgwbvqLlrJJ4LI84Tks33BCDFLX6DjgVm6e6U2si2yjFEVtJmay/+c2GDcy8yXSo8v3JNVCQT9tvy3P1VWlxlrVA4p7G6Zqb2FSzhCCRW0wTXxRhuKhDNaXONWDDs01LTUvTBXUNDuawc1P8TlIJVdQgRd+N6jrSW13kyRHsit5aVL3pLAodQqpF03yP2+j2rzqOJGbereQB6hUJhBD2P4venK0fKKWdT5ENh+GmdJYKyG+LRGU+Hq6X41+1YYywhpecTnhs0Dlhh8MkjWQdageIbNaHIHkCg91HXJsJof3l7W1FJ35+uBEXp7ThGk3Fu45PudPxkXLI/LfbwUiP4pVcB8DOIyrHBADP=='   # noqa E501
]


def identity(it):
    """ Echo back what it gets. """
    return it


good_token_payload = {
    'exp': int(datetime.timestamp(datetime.utcnow() + timedelta(10))),
    'aud': AUDIENCE
}

good_token = jwt.encode(
    good_token_payload,
    JWT_PRIVATE_KEY,
    algorithm=JWT_ALGORITHM)

expired_token = jwt.encode({
    'exp': datetime.utcnow() - timedelta(10),
    'aud': AUDIENCE
},
    JWT_PRIVATE_KEY,
    algorithm=JWT_ALGORITHM)

no_aud_token = jwt.encode({
    'exp': datetime.utcnow() + timedelta(10),
},
    JWT_PRIVATE_KEY,
    algorithm=JWT_ALGORITHM)


class TestExtensionJWTConsumer:
    """Test JWTConsumer."""

    def test_jwt_manager_should_set_defaults(self, dummy_app):
        """Test JWTConsumer defaults."""
        JWTConsumer(dummy_app)
        assert dummy_app.config['JWT_USE_COOKIE'] == False
        assert dummy_app.config['JWT_HEADER_NAME'] == 'Authorization'
        assert dummy_app.config['JWT_HEADER_TYPE'] == 'Bearer'
        assert dummy_app.config['JWT_ALGORITHM'] == 'RS256'
        assert dummy_app.config['JWT_IDENTITY'] is None
        assert dummy_app.config['JWT_AUTHORIZED_KEYS'] is None

    def test_jwt_get_jwt_raw(self, live_testapp):
        """Should run get_jwt_raw and return the token."""
        with mock.patch('flask.request.headers.get',
                        return_value='Bearer Blah'):
            token = get_jwt_raw()
            assert token == 'Blah'

    def test_jwt_get_jwt_raw_empty(self, live_testapp):
        """Should run get_jwt_raw and get raw token."""
        with mock.patch('flask.request.headers.get',
                        return_value=None):
            with pytest.raises(AuthError) as error:
                get_jwt_raw()

            value = error.value
            assert value.code == 401
            assert value.content == {'code': 'authorization_header_missing',
                                     'description': 'Authorization header is expected.'}

    def test_jwt_get_jwt_raw_no_bearer(self, live_testapp):
        """Should run get_jwt_raw and throw an error."""
        with mock.patch('flask.request.headers.get',
                        return_value='Yolo to.ke.n'):
            with pytest.raises(AuthError) as error:
                get_jwt_raw()

            value = error.value
            assert value.code == 401
            assert value.content == {'code': 'invalid_header',
                                     'description': 'Authorization header must start with Bearer.'}

    def test_jwt_get_jwt_raw_no_token(self, live_testapp):
        """Should run get_jwt_raw and throw an error."""
        with mock.patch('flask.request.headers.get',
                        return_value='Bearer'):
            with pytest.raises(AuthError) as error:
                get_jwt_raw()

            value = error.value
            assert value.code == 401
            assert value.content == {'code': 'invalid_header',
                                     'description': 'Token not found.'}

    def test_jwt_get_jwt_raw_extra_stuff(self, live_testapp):
        """Should run get_jwt_raw and throw an error."""
        with mock.patch('flask.request.headers.get',
                        return_value='Bearer token.here.and stuff'):
            with pytest.raises(AuthError) as error:
                get_jwt_raw()

            value = error.value
            assert value.code == 401
            assert value.content == {'code': 'invalid_header',
                                     'description': 'Authorization header must be Bearer token.'}

    def test_jwt_requies_jwt_success(self, live_testapp):
        """Should run through."""
        with mock.patch('flask_jwt_consumer.decorators.get_jwt_raw',
                        return_value=good_token):
            with mock.patch('flask_jwt_consumer.decorators._brute_force_key',
                            return_value=JWT_PUBLIC_KEY):
                protected = requires_jwt(identity)
                assert protected('Yolo') == 'Yolo'

    def test_jwt_requies_jwt_bad_pub_key(self, live_testapp):
        """Should fail."""
        with mock.patch('flask_jwt_consumer.decorators.get_jwt_raw',
                        return_value=good_token):
            with mock.patch('flask_jwt_consumer.decorators._brute_force_key',
                            return_value=RANDOM_PUBLIC_KEY):

                try:
                    protected = requires_jwt(identity)
                    protected('De nada')
                except AuthError as err:
                    assert err.code == 401
                    assert err.content == {'code': 'invalid_header',
                                           'description': 'Unable to parse authentication token.'}

    def test_jwt_requies_jwt_expired_token(self, live_testapp):
        """Should fail."""
        with mock.patch('flask_jwt_consumer.decorators.get_jwt_raw',
                        return_value=expired_token):
            with mock.patch('flask_jwt_consumer.decorators._brute_force_key',
                            return_value=JWT_PUBLIC_KEY):

                try:
                    protected = requires_jwt(identity)
                    protected('De nada')
                except AuthError as err:
                    assert err.code == 401
                    assert err.content == {'code': 'token_expired',
                                           'description': 'Token is expired.'}

    def test_jwt_requies_jwt_no_aud_token(self, live_testapp):
        """Should fail."""
        with mock.patch('flask_jwt_consumer.decorators.get_jwt_raw',
                        return_value=no_aud_token):
            with mock.patch('flask_jwt_consumer.decorators._brute_force_key',
                            return_value=JWT_PUBLIC_KEY):

                try:
                    protected = requires_jwt(identity)
                    protected('De nada')
                except AuthError as err:
                    assert err.code == 401
                    assert err.content == {'code': 'invalid_claims',
                                           'description': 'Missing claims, please check the audience.'}

    def test_jwt_get_jwt_payload(self, live_testapp):
        """Should run through."""
        with mock.patch('flask_jwt_consumer.decorators.get_jwt_raw',
                        return_value=good_token):
            with mock.patch('flask_jwt_consumer.decorators._brute_force_key',
                            return_value=JWT_PUBLIC_KEY):
                protected = requires_jwt(identity)
                protected('Yolo')
                payload = get_jwt_payload()
                assert payload == good_token_payload

    def test_jwt_brute_force_key(self, live_testapp):
        """Should run through."""
        with mock.patch('flask_jwt_consumer.config._Config.decode_keys',
                        new_callable=PropertyMock) as fake_decode_keys:
            fake_decode_keys.return_value = AUTHORIZE_KEYS
            key = _brute_force_key(good_token)
            assert key.find('fbwUiP4pVcB8DOIyrH6m3Q==') == 700

    def test_jwt_brute_force_key_bad_keys(self, live_testapp):
        """Should return no keys."""
        with mock.patch('flask_jwt_consumer.config._Config.decode_keys',
                        new_callable=PropertyMock) as fake_decode_keys:
            fake_decode_keys.return_value = AUTHORIZE_BAD_KEYS
            key = _brute_force_key(good_token)
            assert key is None
