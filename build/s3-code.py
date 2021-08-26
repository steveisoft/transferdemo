import os
import sys
import uuid
import json
import logging
import subprocess
from urllib.parse import unquote_plus
import gzip
from io import BytesIO
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

VIRUSSCANHOST = os.getenv('VIRUSSCANHOST', '0.0.0.0') 
REGION = 'us-east-1'

from utils import *

# One-time Initialization
boto3.setup_default_session(region_name=REGION)
session = boto3.session.Session()
sts = session.client('sts')
ACCOUNT = sts.get_caller_identity().get('Account')

# notification channels
UPLOAD_OBJ = 'obj-upload'
DOWNLOAD_OBJ = 'obj-download'

def send_download_notification(s3, statdict):
    subject = "File received notification"
    sns = boto3.client('sns')
    arn = "arn:aws:sns:{0}:{1}:{2}".format(REGION, ACCOUNT, DOWNLOAD_OBJ)
    try:
        logger.info("Publish to %s" % arn)
        sns.publish(
            TopicArn=arn,
            Message=str(statdict),
            Subject=subject
        )
    except ClientError as e:
        statdict['notified'] = 'failed'
        #logger.warning("Failed to publish notification to %s" % arn)


def send_upload_notification(s3, statdict):
    subject = "File arrival notification"
    if 'virus' in statdict and statdict['virus'] == 'clean':
        statdict['url'] = create_presigned_url(s3, statdict['bucket'], statdict['key'])

    sns = boto3.client('sns')
    arn = "arn:aws:sns:{0}:{1}:{2}".format(REGION, ACCOUNT, UPLOAD_OBJ)
    try:
        logger.info("Publish to %s" % arn)
        sns.publish(
            TopicArn=arn,
            Message=str(statdict),
            Subject=subject
        )
    except ClientError as e:
        statdict['notified'] = 'failed'
        #logger.warning("Failed to publish notification to %s" % arn)


#################
#
# main entry point
#
#################

def lambda_handler(event, context):
    logger.info(json.dumps(event))
    # two kinds of events can be generated; ObjectCreated (uploads) and from Cloudtrail records
    # only 1 object is provided with an ObjectCreated event
    results = []
    for record in event['Records']:
        #logger.info(json.dumps(record))

        bucket = record['s3']['bucket']['name']
        #logger.info(json.dumps(record))
        key = unquote_plus(record['s3']['object']['key'])
        if key.endswith('/'):   # directories aren't interesting
            continue
        # this is part of the notification configuration
        id = record['s3']['configurationId']
        sz = record['s3']['object']['size']
        if sz == 0:
            # a delete?
            logger.info(bucket + ":" + key + ' EMPTY ' + id)
            continue

        if record['eventName'] == 'ObjectCreated:Copy':
            logger.info("NOT Skipping copied obj: {0}".format(bucket + ":" + key))
        # not present in Glacier Restore events
        if 'eTag' in record['s3']['object']:
            etag = record['s3']['object']['eTag']
        etime = record['eventTime']
        userid = "N/A"
        if 'userIdentity' in record:
            # ends in aws-transfer (SFTP)
            # contains StorageGateway-sgw-<ID>
            userid = record['userIdentity']['principalId'] 
        fromip = record['requestParameters']['sourceIPAddress']
        upload_dict = {"bucket": bucket, "key": key, "IP": fromip, "size": sz}
        if userid.find('aws-transfer') > -1:
            upload_dict["method"] = "S3-SFTP"
        elif userid.find('StorageGateway') > -1:
            upload_dict["method"] = "S3-GWay"
        else:
            upload_dict["method"] = "S3"
        logger.info(bucket + ":" + key + ' ' + id)

        if id == "file-upload":
            s3 = session.client('s3')
            if VIRUSSCANHOST == '0.0.0.0': # skip virus scan
                virus_state = "skipped"
            else:
                # Perform virus scan
                download_path = '/tmp/{}'.format(uuid.uuid4())
                virus_state = "failed"
                logger.info("retrieving object to submit for scan")
                try:
                    s3.download_file(bucket, key, download_path)
                    #attempts of doing an anonymous download
                    #s3.download_file(ebucket, ekey, download_path)
                    #s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
                    # replace the IP
                    with open("scan.conf", "r") as f:
                        virusconf = f.read()
                        newconf = virusconf.replace('18.222.126.212', VIRUSSCANHOST)
                    with open("/tmp/scan.conf", "w") as f:
                        f.write(newconf)
                    ret = subprocess.run(["./clamdscan", "--config-file=/tmp/scan.conf", download_path], 
                                         stdout=subprocess.PIPE)
                    virus_state = "clean" if ret.returncode == 0 else "tainted"
                except ClientError as e:
                    logger.warning("clamdscan/retrieve failed: {0}".format(e))
                os.unlink(download_path)

            logger.info("scan state %s" % virus_state)
            upload_dict["virus"] = virus_state
            send_upload_notification(s3, upload_dict)
            results.append(upload_dict)

        if id == "audit-create":
            # download an unpack gzip file
            if key.find("CloudTrail-Digest") >= 0:
                continue
            try:
                s3 = session.client('s3')
                obj = s3.get_object(Bucket=bucket, Key=key)
                n = obj['Body'].read()
                gzipfile = gzip.GzipFile(fileobj = BytesIO(n))
            except ClientError as e:
                logger.warning("failed to read audit record {0} failed: {1}".format(key, e))
                continue
            records = json.load(gzipfile)
            #logger.info(json.dumps(records))
            process_cnt = 0
            skip_cnt = 0
            total_cnt = len(records['Records'])
            logger.info("Cloudtrail: {0} in {1}".format(total_cnt, key))
            for audrec in records['Records']:
                # skip uninteresting events
                if audrec['requestParameters'] is None:
                    skip_cnt += 1
                    continue
                if not 'requestParameters' in audrec:
                    skip_cnt += 1
                    continue
                if not 'bucketName' in audrec['requestParameters']:
                    skip_cnt += 1
                    continue
                if audrec['requestParameters']['bucketName'].find('-cloudtrail-') > -1:
                    skip_cnt += 1
                    continue
                if audrec['eventName'] != "GetObject":   # not a good receipt
                    skip_cnt += 1
                    continue
                if audrec['requestParameters']['key'].startswith('Audit'):
                    skip_cnt += 1
                    continue
                # don't audit my own activity
                if 'S3Notifier' in audrec['userIdentity']['principalId']:
                    skip_cnt += 1
                    continue

                process_cnt += 1
                bucket = audrec['requestParameters']['bucketName']
                key = audrec['requestParameters']['key']
                recvtime = audrec['eventTime']
                fromip = audrec['sourceIPAddress']
                userid = audrec['userIdentity']['principalId']
                arn = None
                if 'arn' in audrec['userIdentity']:
                    arn = audrec['userIdentity']['arn']
                if 'additionalEventData' in audrec \
                        and 'AuthenticationMethod' in audrec['additionalEventData'] \
                        and audrec['additionalEventData']['AuthenticationMethod'] != "AuthHeader":
                    # QueryString/for presigned URL or AuthHeader
                    audrec['userAgent'] = audrec['additionalEventData']['AuthenticationMethod']
                agent = audrec['userAgent'] if 'userAgent' in audrec else 'unknown'

                download_dict = {'IP': fromip, 'method': agent, "size": sz,
                                 'bucket': bucket, 'key': key, 'time': recvtime}
                if download_dict['method'] == 'signin.amazonaws.com':
                    how = "AWS console"
                elif download_dict['method'].find('s3fs') >= 0:
                    how = "S3FS FUSE"
                elif userid.find('storage-gateway') >= 0:
                    how = "S3 Gateway"
                elif userid.find('aws-transfer') >= 0:
                    how = "SFTP Pull"
                elif download_dict['method'].find('Mozilla/5') >= 0:
                    how = "JS Browser"
                elif download_dict['method'] == 'QueryString':
                    how = "Pre-signed URL"
                else:
                    how = download_dict['method'].split()[0][1:] # skip [, e.g [Boto3/1.10.44 [Mozilla/5.0
                download_dict["method"] = how
                if arn:
                    download_dict['recipient'] = arn

                # see if any tags were accumulated
                tags = get_tags(s3, bucket, key)
                for k,v in tags.items():
                    download_dict[k] = v

                send_download_notification(s3, download_dict)
                results.append(upload_dict)

            if process_cnt + skip_cnt != total_cnt:
                logger.warning("Cloudtrail: {0} {1}".format(process_cnt, skip_cnt))

        logger.info("completed record")

    if not 'AWS_LAMBDA_FUNCTION_NAME' in os.environ:
        return results

if __name__ == '__main__':

    #import pdb
    os.environ['VIRUSHOST'] = "127.0.0.1"

    for i in range(1, len(sys.argv)):
        #print("Testing", sys.argv[i])
        with open(sys.argv[i], "r") as f:
            try:
                event = json.loads(f.read())
                print(lambda_handler(event, None))
            except:
                pass

"""
    # s3 upload
    sample_event = {
    "Records": [
        {
            "eventVersion": "2.1",
            "eventSource": "aws:s3",
            "awsRegion": "us-east-1",
            "eventTime": "2021-08-26T02:21:22.713Z",
            "eventName": "ObjectCreated:Put",
            "userIdentity": {
                "principalId": "AWS:AIDAUQSCAYUBLMK2LR533"
            },
            "requestParameters": {
                "sourceIPAddress": "3.238.162.81"
            },
            "responseElements": {
                "x-amz-request-id": "20QEBW6TCEGB810Z",
                "x-amz-id-2": "2TH2wK/fiT9jIlgboFODB4cfK50Y0+/w34XNBjtGGKgbMBwtJyR4av+jg482tInIxtMcpuTsfETLjplbnpqwCbNyvkYSI70aSabaJIgUHMA="
            },
            "s3": {
                "s3SchemaVersion": "1.0",
                "configurationId": "5ff74e81-6379-4118-9c38-b51f97c3508f",
                "bucket": {
                    "name": "demo-transfer-private4",
                    "ownerIdentity": {
                        "principalId": "A13ZTI5Y30L7WD"
                    },
                    "arn": "arn:aws:s3:::demo-transfer-private4"
                },
                "object": {
                    "key": "Transfer/scan.conf",
                    "size": 24035,
                    "eTag": "eb49892d4bf77c31638f7f583f667dd3",
                    "sequencer": "006126FAA40464060B"
                }
            }
        }
    ]
}
"""
