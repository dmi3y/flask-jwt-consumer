"""Defines fixtures available to all tests."""

import pytest
from flask import Flask
from flask_jwt_consumer import JWTManager
from webtest import TestApp

jwtmanager = JWTManager()

def create_app():
    app = Flask(__name__)
    jwtmanager.init_app(app)

    return app

@pytest.fixture
def live_app():
    """An application for the tests."""
    _live_app = create_app()
    ctx = _live_app.test_request_context()
    ctx.push()
    _live_app.config['JWT_IDENTITY'] = 'self-identity'
    yield _live_app

    ctx.pop()


@pytest.fixture
def live_testapp(live_app):
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