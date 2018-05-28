import logging
import boto3
import time
import base64
import gzip
import struct
import re
import os
import json



#Inicializando recursos da AWS
queue_url = "https://sqs.us-east-1.amazonaws.com/102212442704/scan-file"
sqs = boto3.resource('sqs','us-east-1')
queue = sqs.Queue(queue_url)
s3_resource = boto3.resource('s3', region_name='us-east-1')


#inicializando variaveis
max_queue_messages = 1
files_count = 0
bucket_prefix = 'cf'
body = ""
t = time.time()
#os.mkdir(os.environ.get('HOME')+'/myfiles')
#d = os.chdir(os.environ.get('/tmp'))
d = os.chdir('/tmp')

#Loop da chamadas das funcoes
while True:
    print("Checking queue...")
    messages_to_delete = []
    messages = queue.receive_messages(MaxNumberOfMessages=max_queue_messages)

    #Verfica se existe mensagem no SQS
    if len(messages) == 0:
        print("No more messages, waiting 5 seconds")
        time.sleep(5)
        continue

    #loop de uma mensagem no SQS
    for message in messages:
        print('Message found!')
        body = json.loads(message.body)
        #print(body['Message'])
        # print(type(message.body))
        body = json.loads(body["Message"])

        bucket_name = body["Records"][0]["s3"]["bucket"]["name"]
        cflog_filekey = body["Records"][0]["s3"]["object"]["key"]
        print (bucket_name)
        print (cflog_filekey)
        print('Downloading the message  {} '.format(cflog_filekey))
        t2 = time.time()
        try:
            s3_resource.Bucket(bucket_name).download_file(cflog_filekey, "/scan/" + cflog_filekey)
            break
        except (FileNotFoundError, IOError):
            print("Malware Econtrado!")
            response = client.publish(
                TopicArn='arn:aws:sns:us-east-1:102212442704:s3-scan-malware-found',
                Message={
                    'bucket': bucket_name,
                    'file': cflog_filekey
                },
                Subject='Malware Found',
                MessageStructure='json',
                MessageAttributes={
                    'string': {
                        'DataType': 'string',
                        'StringValue': 'string',
                        'BinaryValue': b'bytes'
                    }
                }
            )

        print('Download complete, in %.5f seconds' % (time.time() - t2))

       # os.system("/opt/ds_agent/dsa_control -m \"AntiMalwareManualScan:true\"")

        messages_to_delete.append({'Id': message.message_id,
                                   'ReceiptHandle': message.receipt_handle})
        print("%.5f" % (time.time() - t))

        print('Apagando mensagem: {}'.format(cflog_filekey))
        if len(messages_to_delete) > 0:
            delete_response = queue.delete_messages(Entries=messages_to_delete)
