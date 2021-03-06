"""Defines fixtures available to all tests."""

import pytest
from flask import Flask
from flask_jwt_consumer import JWTConsumer
from webtest import TestApp

jwtconsumer = JWTConsumer()


def create_app():
    app = Flask(__name__)
    jwtconsumer.init_app(app)

    return app


@pytest.fixture
def live_app():
    """An application for the tests."""
    _live_app = create_app()
    ctx = _live_app.test_request_context()
    ctx.push()
    yield _live_app

    ctx.pop()


@pytest.fixture
def live_testapp(live_app):
    """A Webtest app."""
    live_app.config['JWT_IDENTITY'] = 'self-identity'
    return TestApp(live_app)


@pytest.fixture
def live_testapp_no_identity(live_app):
    """A Webtest app."""
    return TestApp(live_app)


@pytest.fixture
def dummy_app():
    """Dummy app."""
    _dummy_app = create_app()
    ctx = _dummy_app.test_request_context()
    ctx.push()
    yield _dummy_app

    ctx.pop()
