import gzip
import json
import base64
import boto3
import os

def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        #.encode('utf8'),
        'headers': {
            'Content-Type': 'application/json',
            #'Content-Type': 'text',
        },
    }


def lambda_handler(event, context):
    
    
    cw_data = event['awslogs']['data']
    #cw_data = str(event['awslogs']['data'])
    #cw_logs = gzip.GzipFile(fileobj=BytesIO(base64.b64decode(cw_data, validate=True))).read()
    compressed_payload = base64.b64decode(cw_data)
    uncompressed_payload = gzip.decompress(compressed_payload)
    payload = json.loads(uncompressed_payload)
    log_events = payload['logEvents']
    #log_events = json.loads(cw_logs)
    for log_event in log_events:
        a = log_event['message']
    print(a)
    log_events_data = json.loads(a)
    
      
    
    source = log_events_data['eventSource']
    nameevent = log_events_data['eventName']
    user = log_events_data['userIdentity']['principalId']
    secret = log_events_data['requestParameters']['secretId']
    msg = "Hi Team,     We have detected the %s event from AWS Secret Manager Service with below details:    Event Source- %s    Event Name- %s    User- %s  Secret-Id- %s " % (nameevent,source,nameevent,user,secret)
    subj = "AWS Notification Message For AWS Secret Event"    
   
    if 'DescribeSecret' in nameevent:
        MY_SNS_TOPIC_ARN = os.environ['snstopic']
        sns_client = boto3.client('sns')
        sns_client.publish(
        TopicArn = MY_SNS_TOPIC_ARN,
        Subject = subj,
        Message = msg
        )
        
        return respond(None, "Thanks for using this command. Sending Mail.....")
    else:

        return respond(None, "Thanks for using this fucntion but event detected is diff:%s" % (nameevent))