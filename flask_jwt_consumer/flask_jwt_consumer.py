# -*- coding: utf-8 -*-
""" Ensures JWT secure communication."""
# Shamelessly (mostly) stolen from https://auth0.com/docs/quickstart/backend/python
# Inspired by https://github.com/vimalloc/flask-jwt-simple.


# Main JWT manager object
class JWTConsumer(object):
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
