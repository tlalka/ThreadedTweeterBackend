Asher's revived ThreadedTweeter project

Site hosted on: https://threaded-tweeter-site.s3.us-east-2.amazonaws.com/index.html

APIs hosted on: https://0n0zjltdyi.execute-api.us-east-1.amazonaws.com/dev

Bucket for uploading user images: arn:aws:s3:::tt-media-bucket/*

Frontend code: https://github.com/tlalka/TTDeploy/branches

What's new?

The previous application ran assuming that the back-end and front-end were on the same domain. They shared information by sharing cookies on the same domain. This required you to purchase a domain and set up an API gateway service, as browsers will not allow cookies to be set to the subdomain of "amazonaws.com". I have changed the code to work with different domains. When the front-end communicates to the back-end, it calls the APIs with headers containing the necessary information. When the back-end communicates with the front end, it uses a query string in the URL. 

The splitting feature has also been improved. Basic splitting searches for the nearest ".", ",", ";", ":", "!", "?" or space to the full character limit to split at. Previously it would crash if it found a tweet without a breaking character, now it just splits at the character limit if it can't find one of these breaking characters. 

As new “SourcePaths.js” file has been added to the front-end project. URLs are no longer hard-coded where they are used, the project looks in this file for the API source path and website Domain. 

Various miscellaneous bugs in the back-end code were fixed as well. 

Deploying ThreadedTweeter Backend + Frontend

Things you will need:
1. An AWS account
2. Twitter API keys 
	go https://developer.twitter.com/en/apply-for-access.html to make/apply for a developer account.
4. A computer with Python 3.6+ and internet

Part 1: The AWS setup
1. Make an IAM user 
	1. Go here: https://console.aws.amazon.com/iam/home?#/users
	2. Click Add user
	3. Put in a username and enable Programmatic access
	4. Click next
	5. Click create group
	6. Set a group name and add AdministratorAccess
	7. Click next until it shows you Access Key Id and Secret Access Key. Save these.
	8. Go to your user summary and also record your User ARN.
 
2. Make the s3 buckets for the frontend and media uploading service.
	1. Make a new bucket for media, call it "media-bucket" or something. 
	2. Go to Permissions -> Bucket Policy.
	3. Paste this in https://gist.github.com/peakay/c0c8aaf57a0ea7eeb0c5dc9d85874011 with necessary modifications. 

Ex:
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
	4. Go to Mamegement, Add Lifecycle rule
	5. Make a name for your rule, click next on Transitions, on Expirations click the Current version and make set some # of days for anything uploaded to the bucket to be automatically purged. For this application, one day is good. 
	6. Click next, review. Done!

Part 2: Backend deploy
0. Make sure you've made an App on twitter. If you already have API keys, then you've done this. If not, make a new app and save the API keys.
1. Clone backend repo -> https://github.com/tlalka/ThreadedTweeterBackend
2. Setup virtualenv https://docs.python-guide.org/dev/virtualenvs/ inside repo directory
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
1. Do this for the frontend https://andela.com/insights/how-to-deploy-your-react-app-to-aws-s3/ Make sure to change references to api.threadedtweeter.com/v2 your backend URL.
2. Copy build files you got in same process as Part 1.2.1
3. Go back to app.py in backend repo, change TT_FRONT_END to a link to your bucket (or domain if you have set that up), and COOKIE_BASE_URL do the same with COOKIE_BASE_URL (put a . in front of the highest level of the domain, i.e. .google.com and not .gmail.google.com)
4. Redeploy backend (zappa update)


Quick start tips:

To deploy the front-end, run this in the “tt-deploy” directory 
npm run build
npm run deploy

To deploy the back-end, run this in the “ThreadedTweeterBackend” directory
source venv/bin/activate
zappa deploy 

^or “zappa update” if already deployed once before
