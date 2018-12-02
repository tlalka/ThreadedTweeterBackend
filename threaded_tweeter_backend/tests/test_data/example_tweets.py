import json
from ...app import APIException

tweet_1 = {'input': json.dumps({
            'TWEETS':[
                {
                    'STATUS':'hello',
                    'MEDIA':[
                    ]
                }
            ]
            }),
            'output': [{'body': 'hello', 'id': 'a random tweet id'}]}

fail_tweet_1 = {'input': json.dumps({
                'TWEETS':[
                    {
                        'STATUS':'hello world',
                        'MEDIA':[]
                    },
                    {  
                        'STATUS': 'THROW AN ERROR',
                        'MEDIA': []
                    }
                ]
                }),
                'output': {'errorMessage': 'Post Error: \nTweets rolled back.'}}