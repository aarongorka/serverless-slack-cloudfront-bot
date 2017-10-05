#!/usr/bin/env python3
import boto3
import time
import os
from dateutil.tz import tzlocal
import datetime
import uuid
import json
from urllib.parse import urlparse, parse_qs
import logging
from urllib.parse import urlencode, quote_plus
import botocore
import logging
import aws_lambda_logging
import requests

aws_lambda_logging.setup(level=os.environ.get('LOGLEVEL', 'INFO'), env=os.environ.get('ENV'))
aws_lambda_logging.setup(level=os.environ.get('LOGLEVEL', 'INFO'), env=os.environ.get('ENV'))


def invalidate(event, context):
    logging.info(json.dumps({'event': event}))
    response_url = parse_qs(event)['response_url'][0]
    selected_url = parse_qs(event)['selected_url'][0]
    logging.debug(json.dumps({'response_url': response_url, "selected_url": selected_url}))
    correlation_id = get_correlation_id(event=event)
    accounts = os.environ.get('BOT_AWS_ACCOUNTS').split(',')
    o = urlparse(selected_url)
    hostname = o.hostname
    path = o.path
    try:
        message = check_accounts_and_invalidate(accounts, hostname, path, correlation_id)
    except:
        message = "An unknown error occurred, please check the logs."
        pass
    post_message(message, response_url, correlation_id)


def post_message(message, response_url, correlation_id):
    data = {
        "text": message
    }
    try:
        r = requests.post(response_url, data=json.dumps(data), timeout=5, headers={'Correlation-Id': correlation_id, 'content-type': 'application/json'})
    except:
        logging.exception(json.dumps({'action': 'post message', 'status': 'failed', 'message': message, 'response_url': response_url}))
        raise
    else:
        logging.info(json.dumps({'action': 'post message', 'status': 'success'}))

    try:
        response = json.loads(r.text)
        logging.debug(json.dumps({'action': 'post message', 'status': 'success', 'response': response}))
    except json.decoder.JSONDecodeError:
        logging.debug(json.dumps({'action': 'post message', 'status': 'success', 'response': r.text}))
    except:
        pass

    try:
        logging.debug(json.dumps({'status code': r.status_code}))
    except:
        pass

    logging.info(json.dumps({'result': 'success!'}))


def respond(event, context):
    """Just invokes the actual task and then responds to Slack"""

    logging.info(json.dumps({'event': event}))

    try:
        body = parse_qs(event['body'])
    except:
        logging.exception(json.dumps({'action': 'parse body', 'status': 'failed'}))
        raise
    else:
        logging.info(json.dumps({'action': 'parse body', 'status': 'success', 'body': body}))

    try:
        correlation_id = get_correlation_id(body=body)
        aws_lambda_logging.setup(level=os.environ.get('LOGLEVEL', 'INFO'), env=os.environ.get('ENV'), correlation_id=correlation_id)
    except:
        logging.exception(json.dumps({"action": "get correlation-id", "status": "failed"}))
        response = {
            "statusCode": 503,
            'headers': {
                'Content-Type': 'application/json',
            }
        }
        return response
    else:
        logging.debug(json.dumps({'action': 'get correlation-id', 'status': 'success', 'correlation_id': correlation_id}))

    selected_url = urlparse(parse_qs(event['body'])['text'][0])
    response_url = parse_qs(event['body'])['response_url'][0]
    logging.debug(json.dumps({'response_url': response_url}))

    try:
        selected_url = body['text'][0]
        urlparse(selected_url)
    except KeyError:
        logging.exception(json.dumps({'action': 'get selected_url', 'status': 'failed'}))
        response = {
            "statusCode": 200,
            "body": json.dumps({"text": "Please provide a valid URL."}),
            'headers': {
                'Content-Type': 'application/json',
            }
        }
        return response
    else:
        logging.info(json.dumps({'action': 'get selected_url', 'status': 'success', 'selected_url': selected_url}))

    data = {
        "selected_url": selected_url,
        "response_url": response_url
    }
    handler = os.environ['INVALIDATE_HANDLER']

    response = invoke_handler(urlencode(data), handler, correlation_id)
    logging.debug(json.dumps({'body': body}))
    response = {
        "statusCode": 200,
        "body": json.dumps({"text": response}),
        'headers': {
            'Content-Type': 'application/json',
        }
    }
    return response


def invoke_handler(data, handler, correlation_id):
    try:
        config = botocore.config.Config(connect_timeout=300, read_timeout=300)
        client = boto3.client('lambda', config=config)
        client.meta.events._unique_id_handlers['retry-config-lambda']['handler']._checker.__dict__['_max_attempts'] = 0
        resp = client.invoke(
            FunctionName=handler,
            InvocationType='Event',
            Payload=json.dumps(data)
        )
        payload = resp['Payload'].read()
    except:
        logging.exception(json.dumps({'action': 'post message', 'status': 'failed', 'data': data, 'handler': handler}))
        return "Something went wrong."
    else:
        logging.info(json.dumps({'action': 'invoke handler', 'status': 'success', 'handler': handler}))
    return "Request received..."


def get_correlation_id(body=None, payload=None, event=None):
    correlation_id = None
    if event is not None:
        try:
            correlation_id = event['headers']['X-Amzn-Trace-Id'].split('=')[1]
        except:
            pass

    if body is not None:
        try:
            correlation_id = body['trigger_id'][0]
        except:
            pass
    elif payload is not None:
        try:
            correlation_id = payload['trigger_id']
        except:
            pass

    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
    return correlation_id


def get_distributions(session):
    client = session.client('cloudfront')
    dists = client.list_distributions()
    try:
        logging.info(json.dumps({'action': 'getting distributions', 'distributions': dists['DistributionList']['Items']}))
    except KeyError:
        return None
    return dists['DistributionList']['Items']


def select_distribution(hostname, distributions):
    cloudfront_id = [x['Id'] for x in distributions if hostname in x['Aliases']['Items']][0]
    return cloudfront_id


def invalidate_path(cloudfront_id, path, correlation_id, session):
    client = session.client('cloudfront')
    invalidation = client.create_invalidation(
        DistributionId=cloudfront_id,
        InvalidationBatch={
            'Paths': {
                'Quantity': 1,
                'Items': [path]
            },
            'CallerReference': correlation_id})
    logging.info(json.dumps({'invalidation': invalidation}))
    if invalidation['ResponseMetadata']['HTTPStatusCode'] == 201:
        response = "The invalidation for {} on distribution {} was successfully submitted.".format(path, cloudfront_id)
    return response


def check_accounts_and_invalidate(accounts, hostname, path, correlation_id):
    cloudfront_id = None
    for account in accounts:
        session = role_arn_to_session(
            RoleArn="arn:aws:iam::{}:role/{}".format(account, os.environ.get('BOT_AWS_ROLE')),
            RoleSessionName=correlation_id)
        distributions = get_distributions(session)
        try:
            cloudfront_id = select_distribution(hostname, distributions)
        except:
            logging.info(json.dumps({"action": "check account", "account": account, "result": "failed"}))
            pass
        if cloudfront_id is not None:
            logging.info(json.dumps({"action": "check account", "account": account, "result": "success"}))
            break

    if cloudfront_id is None:
        return "Could not find CloudFront distribution ID."

    try:
        response = invalidate_path(cloudfront_id, path, correlation_id, session)
    except:
        return "Failed"

    return response


def role_arn_to_session(**args):
    """
    Usage :
        session = role_arn_to_session(
            RoleArn='arn:aws:iam::012345678901:role/example-role',
            RoleSessionName='ExampleSessionName')
        client = session.client('sqs')
    """
    client = boto3.client('sts')
    response = client.assume_role(**args)
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

if __name__ == '__main__':
    respond(event, {})
