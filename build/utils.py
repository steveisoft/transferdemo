import os
import sys
import json
import time
import boto3
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def put_tags(s3, bucket, key, tagdict):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    # Upload the file
    tag_list = []
    try:
        for k,v in tagdict.items():
            tag_list.append({'Key': k, 'Value': v})
        response = s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={'TagSet': tag_list})
    except ClientError as e:
        logger.warn("put_tags fails: {0}".format(e))
    return


def get_tags(s3, bucket, key, version=None):
    """retrieve any tags on an S3 object, usually added by SFTP push, scanner

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    # Upload the file
    try:
        response = s3.get_object_tagging(Bucket=bucket, Key=key)
        retdict = dict()
        for kv in response['TagSet']:
            retdict[kv['Key']] = kv['Value']
        return retdict
    except ClientError as e:
        logger.warn("get_tags failed: {0}".format(e))
        return {}
    return {} 


def create_presigned_url(s3, bucket_name, object_name, expiration=3600):
    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """
    # Generate a presigned URL for the S3 object
    try:
        response = s3.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
    except ClientError as e:
        logger.warn("pre-sign url fails: {0}".format(e))
        return None

    # The response contains the presigned URL
    return response


def s3select(s3, dbkey, query):
    #logger.info(query)
    result = [dict()]
    try:
        response = s3.select_object_content(
            Bucket=ARCHBUCKET, # was MFTBUCKET
            Key=dbkey,
            Expression=query,
            ExpressionType='SQL',
            InputSerialization={
                'CSV': {
                    'FileHeaderInfo': 'USE',
                    'Comments': '#',
                    'QuoteEscapeCharacter': '\\',
                    'RecordDelimiter': '\n',
                    'FieldDelimiter': ',',
                    'QuoteCharacter': '\"',
                    'AllowQuotedRecordDelimiter': False
                },
                'CompressionType': 'GZIP'
            },
            OutputSerialization={
                'JSON': {
                    'RecordDelimiter': ',',
                }
            },
            RequestProgress={
                'Enabled': False
            }
        )

        event_stream = response['Payload']
        end_event_received = False
        for event in event_stream:
            # capture the data from the records event,
            if 'Records' in event:
                #result = json.loads(event['Records']['Payload'][0:-1])
                data = event['Records']['Payload'].decode('utf-8')
                #result = json.loads('[' + data[0:-1] + ']')
                #result = json.loads(data[0:-1])
                result = json.loads('[' + data[0:-1] + ']')
            elif 'Progress' in event:
                pass # print(event['Progress']['Details'])
            elif 'End' in event:
                end_event_received = True
        if not end_event_received:
            raise RuntimeError("End event not received, request incomplete.")
        #logger.info(result)
        return result
    except Exception as e:
        logger.warn("select {0} {1} fails: {2}".format(dbkey, query, e))
        return result


def objexists(s3, bucket, key, delay=0):
    """
       Return T/F if the key exists
    """
    #print("\tChecking for {0}:{1}".format(bucket,key))
    for i in range(0,5):
       fileobj = s3.list_objects_v2(Bucket=bucket, Prefix=key)
       if 'Contents' in fileobj: return True
       if delay > 0:
           time.sleep(delay)
       else:
           break
    return 'Contents' in fileobj


def bucketexists(s3, bucket):
    try:
        s3.head_bucket(Bucket=bucket)
        return True
    except ClientError as e:
        logger.warn("Bucket test {0}: {1}".format(bucket, e))
        return False


def delobject(s3, bucket, key):
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as e:
        logger.error("Failed to dlete {0} -> {1}".format(key, e))
        return False
    return True


def mkfolder(s3, bucket, key):
    # key ends in /
    if not objexists(bucket, key):
        s3.put_object(Bucket=bucket, Body='', Key=key, ACL='bucket-owner-full-control')


def getbucketcontents(s3, bucket, prefix, level=2, suffix='.csv'):
    pagi = s3.get_paginator('list_objects')
    params = {'Bucket': bucket, 'Prefix': prefix}
    iterator = pagi.paginate(**params)
    files = []
    prefixes = []
    for page in iterator:
        if 'Contents' in page:
            for obj in page['Contents']:
                key = obj['Key']
                parts = key.split('/')
                #print(key, len(parts))
                if (suffix == '/' and len(parts) >= level) or (suffix != '/' and len(parts) == level):
                    prefix = '/'.join(parts[0:level])
                    if suffix == '/' and (parts[level-1] == '/' or len(parts) > level):
                        if not prefix in prefixes:
                            prefixes.append(prefix)
                    # find unique prefixes at this level
                    elif key.endswith(suffix):
                        files.append(key)
    if suffix == '/': return prefixes
    return files


def download_file(s3, file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Download the file
    try:
        response = s3.download_file(bucket, object_name, file_name)
        #obj = s3_client.get_object(Bucket=bucket, Key=object_name)
        #with open(file_name, "wb") as f:
        #    f.write(obj['Body'].read())
    except ClientError as e:
        logger.error("Failed to download {0} -> {1}".format(object_name, e))
        return False
    return True


def upload_file(s3, file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    try:
        response = s3.upload_file(file_name, bucket, object_name, ExtraArgs={'ACL': 'bucket-owner-full-control'})
    except ClientError as e:
        logger.error(e)
        return False
    return True
