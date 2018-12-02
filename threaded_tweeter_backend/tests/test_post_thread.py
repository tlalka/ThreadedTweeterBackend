from flask import Flask
import pytest
from .test_base import BaseTestCase
import json
from mock import Mock, patch
from ..app import app
import twitter
from .test_data import example_tweets


class MockTwitterApi:
    def __init__(self, *a, **kw):
        pass
    def PostUpdate(self, status, **kw):
        return MockStatus(status, "a random tweet id")

class MockStatus:
    def __init__(self, status, tweet_id):
        self.text = status
        self.id = tweet_id

class TestPostThread(BaseTestCase):
    def test_post_thread(self):
        test_cases = [example_tweets.tweet_1]
        with patch.object(twitter, 'Api',  MockTwitterApi):
            for test in test_cases:
                assert self.make_post(test['input']) == test['output']
    
    def make_post(self, tweet_json):
        self.client.set_cookie('.threadedtweeter.com', 'access_token_key', 'test123')
        self.client.set_cookie('.threadedtweeter.com', 'access_token_secret', 'test146')
        return json.loads(self.client.post('/v2/post-thread', data=tweet_json).data)
