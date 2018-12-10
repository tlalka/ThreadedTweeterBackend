v2 API for ThreadedTweeter

Deploying ThreadedTweeter Backend + Frontend

Things you will need:
1. An AWS account
2. Twitter API keys
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
	1. Do this for the frontend https://scotch.io/@blizzerand11/deploy-and-sync-a-react-app-to-amazon-s3
	2. Make a new bucket for media, call it "media-bucket" or something. 
	3. Go to Permissions -> Bucket Policy.
	4. Paste this in https://gist.github.com/peakay/c0c8aaf57a0ea7eeb0c5dc9d85874011 with necessary modifications.
	5. Go to Mamagement, Add Lifecycle rule
	6. Make a name for your rule, click next on Transitions, on Expirations click the Current version and make set some # of days for anything uploaded to the bucket to be automatically purged.
	7. Click next, review. Done!

Part 2: Backend deploy
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

Part 3: Frontend deploy
1. Follow instructions here to build frontend. Make sure to change references to api.threadedtweeter.com/v2 to whatever backend URL you just deployed! 
2. Copy build files you got in same process as Part 1.2.1
3. Go back to app.py in backend repo, change TT_FRONT_END to a link to your bucket (or domain if you have set that up), and COOKIE_BASE_URL do the same with COOKIE_BASE_URL (put a . in front of the highest level of the domain, i.e. .google.com and not .gmail.google.com)
4. Redeploy backend (zappa update)
