from ..app import app
from flask_testing import TestCase


class BaseTestCase(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        return app


class TestSplashPage(BaseTestCase):
    def test_splash_page(self):
        assert self.client.get('/v2').data == b'Welcome to the ThreadedTweeter v2 API!'