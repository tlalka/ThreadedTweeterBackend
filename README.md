v2 API for ThreadedTweeter

Deploying ThreadedTweeter Backend + Frontend

Things you will need:
1. An AWS account
2. Twitter API keys (go https://developer.twitter.com/en/apply-for-access.html to make/apply for a developer account, not hard to get!)
2. A computer with Python 3.6+ and internet

Part 1: The AWS setup.
1. Make an IAM user 
	1. Go here: https://console.aws.amazon.com/iam/home?#/users
	2. Click Add user
	3. Put in a cool username (not required) and enable Programmatic access
	4. Click next
	5. Click create group
	6. Set a group name and add AdministratorAccess (you probably don't want to do this in reality, the only services we use are S3 + Lambda + API Gateway)
	7. Click next until it shows you Access Key Id and Secret Access Key. Remember these!
	8. Go to your user summary and also remember your User ARN.
	9. Done!
 
2. Make the s3 buckets for the frontend and media uploading service.
	1. Do this for the frontend https://andela.com/insights/how-to-deploy-your-react-app-to-aws-s3/
	2. Make a new bucket for media, call it "media-bucket" or something. 
	3. Go to Permissions -> Bucket Policy.
	4. Paste this in https://gist.github.com/peakay/c0c8aaf57a0ea7eeb0c5dc9d85874011 with necessary modifications. Ex:

{
    "Version": "2012-10-17",
    "Id": "Policy1540246581673",
    "Statement": [
        {
            "Sid": "Stmt1540246577650",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::220564146530:user/ThreadedTweeter"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::tt-media-bucket/*"
        }
    ]
}
	6. Go to Mamagement, Add Lifecycle rule
	7. Make a name for your rule, click next on Transitions, on Expirations click the Current version and make set some # of days for anything uploaded to the bucket to be automatically purged.
	8. Click next, review. Done!

Part 2: Backend deploy
0. Make sure you've made an App on twitter. If you already have API keys, then you've done this. If not, make a new app and get some API keys!
1. Clone backend repo -> https://github.com/peakay/ThreadedTweeterBackend
2. Setup virtualenv https://docs.python-guide.org/dev/virtualenvs/ (NOTE, not pipenv, pipenv sucks) inside repo directory
3. Activate it
4. Install requirements. pip install -r requirements.txt
5. Go to threaded_tweeter_backend/app.y and change the os.environ values to appropriate key values. client_key refers to Twitter access key and client_secret refers to Twitter secret key. aws_key refers to AWS key ID and aws_secret refers to AWS secret access key
6. This repo contains a fully functional flask deploy. If you don't want to use lambda/api gateway and instead want to host it on a regular server, all you have to do is run app.py If this is what you want to do, skip to step 11
7. Delete zappa_settings.json 
8. Run zappa init, follow instructions
9. Run zappa deploy, should take several minutes
10. If successful, it should give you a link to the backend. Go to it and see if you can see the splash page! Remember to add /v2 to the URL. 
11. Go back to app.py and change TT_API_URL to the URL you got from Zappa or whatever domain name you have pointed at your server if you are just running Flask.
12. Go to your Twitter developer dashboard -> Apps -> the ThreadedTweeter app -> Add v2/login/verify route to allowed callback url. Add /v2/cliverifier route if you want to support CLI requests. 

Part 3: Frontend deploy
1. Follow instructions here to build frontend. Make sure to change references to api.threadedtweeter.com/v2 to whatever backend URL you just deployed! 
2. Copy build files you got in same process as Part 1.2.1
3. Go back to app.py in backend repo, change TT_FRONT_END to a link to your bucket (or domain if you have set that up), and COOKIE_BASE_URL do the same with COOKIE_BASE_URL (put a . in front of the highest level of the domain, i.e. .google.com and not .gmail.google.com)
4. Redeploy backend (zappa update)


Current Problems:
1. Explore generate_presigned_post fields in get_upload_url(). I believe there's more you can do to accept certain file types.
2. Broken redirect. I think this works on Flask but not on Lambda+API Gateway
3. Doesn't use Dependency Injection. Couldn't figure out how Flask Dependency Injection works (if you want to do it at that level).
4. Messy/ugly auth code. Could probably be cleaned up. 
5. Needs a better method of storing keys. Manually set with os.environ at launch.
6. Doesn't use https :( 

Future tests:
I've provided an outline of how you construct tests with Flask, but this method uses patching. 
1. Doesn't test login flow whatsoever. 
2. Only superficially tests post_thread, could probably be better.
3. Basically there aren't many tests.
