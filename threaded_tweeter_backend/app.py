from flask import Flask, request, make_response, jsonify, redirect
import requests
from requests_oauthlib import OAuth1
from urllib.parse import parse_qs
import os
import json
import boto3
import uuid
import twitter
import datetime
from flask_cors import CORS


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

TWITTER_OAUTH = 'https://api.twitter.com/oauth'
TT_API_URL = 'https://api.threadedtweeter.com/v2'
TT_FRONT_END = 'http://threadedtweeter.com'
domain_white_list = ['http://threadedtweeter.com', 'http://www.threadedtweeter.com']

expire_date = datetime.datetime.now()
expire_date = expire_date + datetime.timedelta(days=180)

COOKIE_BASE_URL = '.threadedtweeter.com'
os.environ['client_key'] = 'JWaFgM9ife7nSVwTYqvwE0GHn'
os.environ['client_secret'] = 'aI9HV8Usd4BUEzb9A1OpcwP4uGvmDBecpC1untLnNQxB5IFiLk'
os.environ['aws_key'] = 'AKIATGWVFZFROEEDDYLM'
os.environ['aws_secret'] = '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'


@app.route('/v2/login')
def get_login_url():
    # Asks Twitter to give us a login URL to send to the user
    request_token_url = f'{TWITTER_OAUTH}/request_token'
    base_authorization_url = f'{TWITTER_OAUTH}/authorize'
    
    oauth_callback = f'{TT_API_URL}/login/verify'
    mode = request.args.get('mode')
    if mode == 'CLI':
        oauth_callback = f'{TT_API_URL}/cliverifier'

    oauth = OAuth1(os.environ['client_key'], client_secret=os.environ['client_secret'])
    r = requests.post(url=request_token_url, auth=oauth, params={'oauth_callback': oauth_callback})
    credentials = parse_qs(r.content)
    resource_owner_key = credentials.get(b'oauth_token')[0].decode('utf-8')
    resource_owner_secret = credentials.get(b'oauth_token_secret')[0].decode('utf-8')
    authorize_url = base_authorization_url + '?oauth_token='
    authorize_url = authorize_url + resource_owner_key
    res = {
        'url': authorize_url,
        'cookie_1': f'resource_owner_key={resource_owner_key}; domain={COOKIE_BASE_URL}',
        'cookie_2': f'resource_owner_secret={resource_owner_secret}; domain={COOKIE_BASE_URL}',
    }
    
    flask_resp = make_response(jsonify(res), 200)
    flask_resp.set_cookie('resource_owner_key', resource_owner_key, domain=COOKIE_BASE_URL, expires=expire_date)
    flask_resp.set_cookie('resource_owner_secret', resource_owner_secret, domain=COOKIE_BASE_URL, expires=expire_date)
    return flask_resp

@app.route('/v2/login/verify')
def verify_login():
    # Receives callback from Twitter containing verifier token, uses this token to ask Twitter for 
    # API credentials
    access_token_url = f'{TWITTER_OAUTH}/access_token'
    if 'resource_owner_key' not in request.cookies and 'resource_owner_secret' not in request.cookies:
        return APIException('Unauthorized: Login cookies not found. Try logging in again.', 401).get_exception()
    oauth_verifier = request.args.get('oauth_verifier')
    if oauth_verifier is None:
        return APIException('Unauthorized: Missing oauth_verifier', 401).get_exception()

    resource_owner_key = request.cookies.get('resource_owner_key')
    resource_owner_secret = request.cookies.get('resource_owner_secret')

    try:
        oauth = OAuth1(os.environ['client_key'],
                        client_secret=os.environ['client_secret'],
                        resource_owner_key=resource_owner_key,
                        resource_owner_secret=resource_owner_secret,
                        verifier=oauth_verifier)
        r = requests.post(url=access_token_url, auth=oauth)
        r.raise_for_status()
    except Exception as e:
        return APIException('Unauthorized: Oauth credentials incorrect. Try logging in again.', 401).get_exception()
    credentials = parse_qs(r.content)
    access_key = credentials.get(b'oauth_token')[0].decode('utf-8')
    access_secret = credentials.get(b'oauth_token_secret')[0].decode('utf-8')
    res = {'cookie_1': f'access_token_key={access_key}; domain={COOKIE_BASE_URL}', 'cookie_2': f'access_token_secret={access_secret}; domain={COOKIE_BASE_URL}'}
    flask_resp = make_response(redirect(TT_FRONT_END, 200))
    flask_resp.set_cookie('access_token_key', access_key, domain=COOKIE_BASE_URL, expires=expire_date)
    flask_resp.set_cookie('access_token_secret', access_secret, domain=COOKIE_BASE_URL, expires=expire_date)
    return flask_resp

@app.route('/v2/post-thread', methods=['POST'])
def post_thread():
    # Posts the thread, on error, deletes from the first posted tweet.
    if 'access_token_key' not in request.cookies and 'access_token_secret' not in request.cookies:
        return APIException('Unauthorized: Login cookies not found. Try logging in again.', 401).get_exception()

    status_json = json.loads(request.data)
    access_token_key = request.cookies.get('access_token_key')
    access_token_secret = request.cookies.get('access_token_secret')

    try:
        api = twitter.Api(consumer_key=os.environ['client_key'], consumer_secret=os.environ['client_secret'],
                          access_token_key=access_token_key, access_token_secret=access_token_secret)
    except Exception as e:
        return APIException('Unauthorized: Unable to verify authentication tokens. Try logging in again!', 401).get_exception()

    reply_to = None
    post_res = []
    head_tweet = None
    for i, tweet in enumerate(status_json['TWEETS'], start=1):
        try:
            status = api.PostUpdate(tweet['STATUS'], in_reply_to_status_id=reply_to, media=tweet['MEDIA'])
            post_res.append({'body': status.text, 'id': status.id})
            reply_to = status.id
            if head_tweet is None:
                head_tweet = status.id
        except Exception as e:
            # do rollback
            if head_tweet:
                # only do rollback logic if it succeeded in posting at least 1 tweet
                user = api.VerifyCredentials().id
                statuses = api.GetReplies(head_tweet, trim_user=True)
                # delete inclusively
                head = api.DestroyStatus(head_tweet)
                for status in statuses:
                    if status.user.id == user:
                        api.DestroyStatus(status.id)

            return APIException(f'Post Error: {str(e)}\n on tweet: #{i} "{tweet["STATUS"]}". Tweets rolled back.', 400).get_exception()

    return json.dumps(post_res)

@app.route('/v2/upload')
def get_upload_url():
    # Generates S3 Upload URL for media uploading prior to sending to Twitter.
    upload_key = uuid.uuid4().hex
    
    session = boto3.session.Session(
          aws_access_key_id=os.environ['aws_key'], 
          aws_secret_access_key=os.environ['aws_secret'])
    
    s3 = session.client('s3')
    fields = {"acl": "public-read"}
    
    # Ensure that the ACL isn't changed and restrict the user to a length
    # between 10 and 100.
    conditions = [
        {"acl": "public-read"},
        ["content-length-range", 10, 10000000]
        ]
    
    # Generate the POST attributes
    post = s3.generate_presigned_post(
        Bucket='threadtweeter-media',
        Key=upload_key+'/${filename}',
        Fields=fields,
        Conditions=conditions,
        ExpiresIn=500
    )

    return json.dumps(post)

@app.route('/v2/login/status')
def is_logged_in():
    # Checks Twitter API creds in cookies and returns login status + username.
    if 'access_token_key' in request.cookies and 'access_token_secret' in request.cookies:
        access_token_key = request.cookies.get('access_token_key')
        access_token_secret = request.cookies.get('access_token_secret')
        api = twitter.Api(consumer_key=os.environ['client_key'],
                          consumer_secret=os.environ['client_secret'],
                          access_token_key=access_token_key,
                          access_token_secret=access_token_secret)
        try:
            creds = api.VerifyCredentials()
            flask_resp = make_response(jsonify({'Status': True, 'username': creds.screen_name}))
            flask_resp.set_cookie('username', creds.screen_name, expires=expire_date)
            return flask_resp
        except Exception as e:
            pass
    return json.dumps({'Status': False}), 401

@app.route('/v2/cliverifier')
def get_cli_verifier():
    # Same idea as /v2/login/verify, except captures the verifier from the callback and asks the CLI user
    # to manually input it in CLI, so that the CLI handles the API cred fetching. 
    oauth_verifier = request.args.get('oauth_verifier')
    if oauth_verifier:
        html = f'<html><head><title>ThreadedTweeter Verifier Token</title></head><body><h1>Your verifier token is: {oauth_verifier} </h1></body></html>'
        return html

@app.route('/v2')
def api_splash():
    return 'Welcome to the ThreadedTweeter v2 API!'

@app.after_request
def after_request(response):
    r = request.referrer[:-1]
    if r in domain_white_list:
        response.headers.add('Access-Control-Allow-Origin', r)
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == '__main__':
    app.run()

class APIException:

    def __init__(self, message, status_code):
        self.message = json.dumps({'errorMessage': message})
        self.status_code = status_code

    def get_exception(self):
        return self.message, self.status_code
