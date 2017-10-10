#!/usr/bin/env python3
import boto3
import time
import os
from dateutil.tz import tzlocal
from dateutil.tz import tzutc
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
import unittest
from unittest.mock import patch
import responses
from requests.exceptions import HTTPError
from botocore.exceptions import ClientError

aws_lambda_logging.setup(level=os.environ.get('LOGLEVEL', 'INFO'), env=os.environ.get('ENV'))
aws_lambda_logging.setup(level=os.environ.get('LOGLEVEL', 'INFO'), env=os.environ.get('ENV'))


def invalidate(event, context):
    logging.info(json.dumps({'event': event}))
    response_url = parse_qs(event)['response_url'][0]
    selected_url = parse_qs(event)['selected_url'][0]
    logging.debug(json.dumps({'response_url': response_url, "selected_url": selected_url}))
    correlation_id = get_correlation_id(event=event)
    accounts = os.environ.get('BOT_AWS_ACCOUNTS').split(',')
    wildcard = False
    wildcard = '*' in selected_url
    if wildcard:
        selected_url = selected_url.replace('*', 'WILDCARD')  # urlparse doesn't understand wildcards, so just replace it with a string for now
    o = urlparse(selected_url)
    hostname = o.hostname
    path = o.path
    try:
        message = check_accounts_and_invalidate(accounts, hostname, path, wildcard, correlation_id)
    except:
        logging.exception(json.dumps({'action': 'invalidate', 'status': 'failed'}))
        message = "An unknown error occurred, please check the logs."
        pass
    post_message(message, response_url, correlation_id)


class post_message_tests(unittest.TestCase):
    @responses.activate
    def test_200_response(self, *args):
        message = "Testing"
        response_url = "https://localhost/path"
        responses.add(responses.POST, response_url, json={'error': 'None'}, status=200)
        correlation_id = get_correlation_id()
        r = post_message(message, response_url, correlation_id)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(json.loads(r.text), {"error": "None"})

    @responses.activate
    def test_404_response(self, *args):
        response_url = "https://localhost/path"
        responses.add(responses.POST, response_url, json={'error': 'not found'}, status=404)
        message = "Testing"
        correlation_id = get_correlation_id()
        r = post_message(message, response_url, correlation_id)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(json.loads(r.text), {"error": "not found"})

    @responses.activate
    def test_exception(self, *args):
        response_url = "https://localhost/path"
        responses.add(responses.POST, response_url, body=HTTPError(), status=500)
        message = "Testing"
        correlation_id = get_correlation_id()
        with self.assertRaises(HTTPError):
            r = post_message(message, response_url, correlation_id)


def post_message(message, response_url, correlation_id):
    data = {
        "text": message,
        "response_type": "in_channel"
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

    logging.info(json.dumps({'action': 'final result', 'result': 'success!'}))
    return r


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
        user_id = body['user_id'][0]
        user_name = body['user_name'][0]
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
        "response_url": response_url,
        "user_name": user_name,
        "user_id": user_id
    }
    handler = os.environ['INVALIDATE_HANDLER']

    response = invoke_handler(data, handler, correlation_id)
    logging.debug(json.dumps({'body': body}))
    response = {
        "statusCode": 200,
        "body": json.dumps({"text": response, "response_type": "in_channel"}),
        'headers': {
            'Content-Type': 'application/json',
        }
    }
    logging.info(json.dumps({'response': response}))
    return response


def invoke_handler(data, handler, correlation_id):
    try:
        config = botocore.config.Config(connect_timeout=300, read_timeout=300)
        client = boto3.client('lambda', config=config)
        client.meta.events._unique_id_handlers['retry-config-lambda']['handler']._checker.__dict__['_max_attempts'] = 0
        resp = client.invoke(
            FunctionName=handler,
            InvocationType='Event',
            Payload=json.dumps(urlencode(data))
        )
        payload = resp['Payload'].read()
    except:
        logging.exception(json.dumps({'action': 'post message', 'status': 'failed', 'data': data, 'handler': handler}))
        return "Something went wrong."
    else:
        logging.info(json.dumps({'action': 'invoke handler', 'status': 'success', 'handler': handler}))
    return "Request to invalidate {} received from {}...".format(data['selected_url'], data['user_name'])


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


class get_distributions_tests(unittest.TestCase):

    def test_valid(self, *args):
        class mock_session:
            def client(*args):
                return mock_client

        class mock_client:
            def list_distributions(*args):
                return {
                    'ResponseMetadata': {'RequestId': '7b8e5977-ad43-11e7-b5d0-15e41e113f8d', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '7b8e5977-ad43-11e7-b5d0-15e41e113f8d', 'content-type': 'text/xml', 'content-length': '9865', 'vary': 'Accept-Encoding', 'date': 'Mon, 09 Oct 2017 22:45:00 GMT'}, 'RetryAttempts': 0}, 'DistributionList': {'Marker': '', 'MaxItems': 100, 'IsTruncated': False, 'Quantity': 3, 'Items': [{'Id': 'SDFSDFSDFSDFDS', 'ARN': 'arn:aws:cloudfront::123456789123:distribution/SDFSDFSDFSDFDS', 'Status': 'Deployed', 'LastModifiedTime': datetime.datetime(2017, 8, 29, 11, 40, 31, 188000, tzinfo=tzutc()), 'DomainName': 'dx0b1hzmj75qi.cloudfront.net', 'Aliases': {'Quantity': 1, 'Items': ['cdn1.dev.foobar.com.au']}, 'Origins': {'Quantity': 3, 'Items': [{'Id': 'S3-cdn-dev-green', 'DomainName': 'cdn-dev-green.s3.amazonaws.com', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'S3OriginConfig': {'OriginAccessIdentity': ''}}, {'Id': 'Custom-test-temp.dev.foobar.com.au', 'DomainName': 'test-cdn.dev.foobar.com.au', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'CustomOriginConfig': {'HTTPPort': 80, 'HTTPSPort': 443, 'OriginProtocolPolicy': 'match-viewer', 'OriginSslProtocols': {'Quantity': 3, 'Items': ['TLSv1', 'TLSv1.1', 'TLSv1.2']}, 'OriginReadTimeout': 30, 'OriginKeepaliveTimeout': 5}}, {'Id': 'S3-cdn-dev', 'DomainName': 'cdn-dev.s3.amazonaws.com', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'S3OriginConfig': {'OriginAccessIdentity': ''}}]}, 'DefaultCacheBehavior': {'TargetOriginId': 'S3-cdn-dev', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0}, 'ViewerProtocolPolicy': 'allow-all', 'MinTTL': 0, 'AllowedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 86400, 'MaxTTL': 31536000, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}, 'CacheBehaviors': {'Quantity': 2, 'Items': [{'PathPattern': '/green/*', 'TargetOriginId': 'S3-cdn-dev-green', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0}, 'ViewerProtocolPolicy': 'allow-all', 'MinTTL': 0, 'AllowedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 86400, 'MaxTTL': 31536000, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}, {'PathPattern': '/ec2/*', 'TargetOriginId': 'Custom-test-temp.dev.foobar.com.au', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0}, 'ViewerProtocolPolicy': 'allow-all',
                    'MinTTL': 15, 'AllowedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 15, 'MaxTTL': 16, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}]}, 'CustomErrorResponses': {'Quantity': 0}, 'Comment': '', 'PriceClass': 'PriceClass_All', 'Enabled': False, 'ViewerCertificate': {'CloudFrontDefaultCertificate': True, 'MinimumProtocolVersion': 'TLSv1', 'CertificateSource': 'cloudfront'}, 'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}}, 'WebACLId': '', 'HttpVersion': 'HTTP2', 'IsIPV6Enabled': True}, {'Id': 'SDFSDF987SDF', 'ARN': 'arn:aws:cloudfront::123456789123:distribution/SDFSDF987SDF', 'Status': 'Deployed', 'LastModifiedTime': datetime.datetime(2017, 8, 29, 11, 40, 31, 446000, tzinfo=tzutc()), 'DomainName': 'd2zb6x7raib769.cloudfront.net', 'Aliases': {'Quantity': 1, 'Items': ['cdn-green.dev.foobar.com.au']}, 'Origins': {'Quantity': 1, 'Items': [{'Id': 'S3-cdn-dev-green', 'DomainName': 'cdn-dev-green.s3.amazonaws.com', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'S3OriginConfig': {'OriginAccessIdentity': ''}}]}, 'DefaultCacheBehavior': {'TargetOriginId': 'S3-cdn-dev-green', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0}, 'ViewerProtocolPolicy': 'allow-all', 'MinTTL': 0, 'AllowedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 86400, 'MaxTTL': 31536000, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}, 'CacheBehaviors': {'Quantity': 0}, 'CustomErrorResponses': {'Quantity': 0}, 'Comment': '', 'PriceClass': 'PriceClass_All', 'Enabled': False, 'ViewerCertificate': {'CloudFrontDefaultCertificate': True, 'MinimumProtocolVersion': 'TLSv1', 'CertificateSource': 'cloudfront'}, 'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}}, 'WebACLId': '', 'HttpVersion': 'HTTP2', 'IsIPV6Enabled': True}, {'Id': 'SDF987SDFSDF', 'ARN': 'arn:aws:cloudfront::123456789123:distribution/SDF987SDFSDF', 'Status': 'Deployed', 'LastModifiedTime': datetime.datetime(2017, 10, 9, 3, 26, 14, 996000, tzinfo=tzutc()), 'DomainName': 'dmr6sy3io0678.cloudfront.net', 'Aliases': {'Quantity': 1, 'Items': ['labs.dev.foobar.com.au']}, 'Origins': {'Quantity': 1, 'Items': [{'Id': 'S3-amaysim-labs-ga', 'DomainName': 'amaysim-labs-ga.s3.amazonaws.com', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'S3OriginConfig': {'OriginAccessIdentity': ''}}]}, 'DefaultCacheBehavior': {'TargetOriginId': 'S3-amaysim-labs-ga', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0},
                    'ViewerProtocolPolicy': 'https-only', 'MinTTL': 0, 'AllowedMethods': {'Quantity': 7, 'Items': ['HEAD', 'DELETE', 'POST', 'GET', 'OPTIONS', 'PUT', 'PATCH'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 86400, 'MaxTTL': 31536000, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}, 'CacheBehaviors': {'Quantity': 0}, 'CustomErrorResponses': {'Quantity': 0}, 'Comment': '', 'PriceClass': 'PriceClass_All', 'Enabled': True, 'ViewerCertificate': {'ACMCertificateArn': 'arn:aws:acm:us-east-1:123456789123:certificate/ccdd8a1d-831c-4bd2-9f94-95c8d17196df', 'SSLSupportMethod': 'sni-only', 'MinimumProtocolVersion': 'TLSv1.1_2016', 'Certificate': 'arn:aws:acm:us-east-1:123456789123:certificate/ccdd8a1d-831c-4bd2-9f94-95c8d17196df', 'CertificateSource': 'acm'}, 'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}}, 'WebACLId': '', 'HttpVersion': 'HTTP2', 'IsIPV6Enabled': True}]}}
        session = mock_session
        account = 123456789123
        result = get_distributions(session, account)
        self.assertTrue(result)

    def test_invalid(self, *args):

        class mock_session:
            def client(*args):
                return mock_client

        class mock_client:
            def list_distributions(*args):
                return {'ResponseMetadata': {'RequestId': '7b8e5977-ad43-11e7-b5d0-15e41e113f8d', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '7b8e5977-ad43-11e7-b5d0-15e41e113f8d', 'content-type': 'text/xml', 'content-length': '9865', 'vary': 'Accept-Encoding', 'date': 'Mon, 09 Oct 2017 22:45:00 GMT'}, 'RetryAttempts': 0}, 'DistributionList': {'Marker': '', 'MaxItems': 100, 'IsTruncated': False, 'Quantity': 3, 'Items': []}}
        session = mock_session
        account = 123456789123
        result = get_distributions(session, account)
        self.assertEqual(result, None)

    def test_failed_session(self, *args):
        class mock_session:
            def client(*args):
                return mock_client

        class mock_client:
            def list_distributions(*args):
                return {}
        session = {}
        account = 123456789123
        result = get_distributions(session, account)
        self.assertEqual(result, None)


def get_distributions(session, account):
    dists = []
    try:
        client = session.client('cloudfront')
        response = client.list_distributions()
        dists = response['DistributionList']['Items']
    except:
        logging.warning(json.dumps({'action': 'getting distributions', 'status': 'failed', 'distributions': None, 'account': account}))
    if dists == []:
        return None
    try:
        keys = ['Id', 'Aliases']
        logging_dists = []
        for dist in dists:
            logging_dists.append({k: dist[k] for k in keys})
        logging.info(json.dumps({'action': 'getting distributions', 'distributions': logging_dists, 'account': account}))
    except:
        logging.exception(json.dumps({'action': 'logging distributions', 'status': 'failed'}))
        pass
    return dists


class select_distribution_tests(unittest.TestCase):
    def test_valid(self, *args):
        distributions = [{
            'Id': 'SDFSDFSDFSDFDS', 'ARN': 'arn:aws:cloudfront::123456789123:distribution/SDFSDFSDFSDFDS', 'Status': 'Deployed', 'LastModifiedTime': datetime.datetime(2017, 8, 29, 11, 40, 31, 188000, tzinfo=tzutc()), 'DomainName': 'dx0b1hzmj75qi.cloudfront.net', 'Aliases': {'Quantity': 1, 'Items': ['cdn1.dev.foobar.com.au']}, 'Origins': {'Quantity': 3, 'Items': [{'Id': 'S3-cdn-dev-green', 'DomainName': 'cdn-dev-green.s3.amazonaws.com', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'S3OriginConfig': {'OriginAccessIdentity': ''}}, {'Id': 'Custom-test-temp.dev.foobar.com.au', 'DomainName': 'test-cdn.dev.foobar.com.au', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'CustomOriginConfig': {'HTTPPort': 80, 'HTTPSPort': 443, 'OriginProtocolPolicy': 'match-viewer', 'OriginSslProtocols': {'Quantity': 3, 'Items': ['TLSv1', 'TLSv1.1', 'TLSv1.2']}, 'OriginReadTimeout': 30, 'OriginKeepaliveTimeout': 5}}, {'Id': 'S3-cdn-dev', 'DomainName': 'cdn-dev.s3.amazonaws.com', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'S3OriginConfig': {'OriginAccessIdentity': ''}}]}, 'DefaultCacheBehavior': {'TargetOriginId': 'S3-cdn-dev', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0}, 'ViewerProtocolPolicy': 'allow-all', 'MinTTL': 0, 'AllowedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 86400, 'MaxTTL': 31536000, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}, 'CacheBehaviors': {'Quantity': 2, 'Items': [{'PathPattern': '/green/*', 'TargetOriginId': 'S3-cdn-dev-green', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0}, 'ViewerProtocolPolicy': 'allow-all', 'MinTTL': 0, 'AllowedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 86400, 'MaxTTL': 31536000, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}, {'PathPattern': '/ec2/*', 'TargetOriginId': 'Custom-test-temp.dev.foobar.com.au', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0}, 'ViewerProtocolPolicy': 'allow-all',
           'MinTTL': 15, 'AllowedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 15, 'MaxTTL': 16, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}]}, 'CustomErrorResponses': {'Quantity': 0}, 'Comment': '', 'PriceClass': 'PriceClass_All', 'Enabled': False, 'ViewerCertificate': {'CloudFrontDefaultCertificate': True, 'MinimumProtocolVersion': 'TLSv1', 'CertificateSource': 'cloudfront'}, 'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}}, 'WebACLId': '', 'HttpVersion': 'HTTP2', 'IsIPV6Enabled': True}, {'Id': 'SDFSDF987SDF', 'ARN': 'arn:aws:cloudfront::123456789123:distribution/SDFSDF987SDF', 'Status': 'Deployed', 'LastModifiedTime': datetime.datetime(2017, 8, 29, 11, 40, 31, 446000, tzinfo=tzutc()), 'DomainName': 'd2zb6x7raib769.cloudfront.net', 'Aliases': {'Quantity': 1, 'Items': ['cdn-green.dev.foobar.com.au']}, 'Origins': {'Quantity': 1, 'Items': [{'Id': 'S3-cdn-dev-green', 'DomainName': 'cdn-dev-green.s3.amazonaws.com', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'S3OriginConfig': {'OriginAccessIdentity': ''}}]}, 'DefaultCacheBehavior': {'TargetOriginId': 'S3-cdn-dev-green', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0}, 'ViewerProtocolPolicy': 'allow-all', 'MinTTL': 0, 'AllowedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 86400, 'MaxTTL': 31536000, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}, 'CacheBehaviors': {'Quantity': 0}, 'CustomErrorResponses': {'Quantity': 0}, 'Comment': '', 'PriceClass': 'PriceClass_All', 'Enabled': False, 'ViewerCertificate': {'CloudFrontDefaultCertificate': True, 'MinimumProtocolVersion': 'TLSv1', 'CertificateSource': 'cloudfront'}, 'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}}, 'WebACLId': '', 'HttpVersion': 'HTTP2', 'IsIPV6Enabled': True}, {'Id': 'SDF987SDFSDF', 'ARN': 'arn:aws:cloudfront::123456789123:distribution/SDF987SDFSDF', 'Status': 'Deployed', 'LastModifiedTime': datetime.datetime(2017, 10, 9, 3, 26, 14, 996000, tzinfo=tzutc()), 'DomainName': 'dmr6sy3io0678.cloudfront.net', 'Aliases': {'Quantity': 1, 'Items': ['labs.dev.foobar.com.au']}, 'Origins': {'Quantity': 1, 'Items': [{'Id': 'S3-amaysim-labs-ga', 'DomainName': 'amaysim-labs-ga.s3.amazonaws.com', 'OriginPath': '', 'CustomHeaders': {'Quantity': 0}, 'S3OriginConfig': {'OriginAccessIdentity': ''}}]}, 'DefaultCacheBehavior': {'TargetOriginId': 'S3-amaysim-labs-ga', 'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}, 'Headers': {'Quantity': 0}, 'QueryStringCacheKeys': {'Quantity': 0}}, 'TrustedSigners': {'Enabled': False, 'Quantity': 0},
           'ViewerProtocolPolicy': 'https-only', 'MinTTL': 0, 'AllowedMethods': {'Quantity': 7, 'Items': ['HEAD', 'DELETE', 'POST', 'GET', 'OPTIONS', 'PUT', 'PATCH'], 'CachedMethods': {'Quantity': 2, 'Items': ['HEAD', 'GET']}}, 'SmoothStreaming': False, 'DefaultTTL': 86400, 'MaxTTL': 31536000, 'Compress': False, 'LambdaFunctionAssociations': {'Quantity': 0}}, 'CacheBehaviors': {'Quantity': 0}, 'CustomErrorResponses': {'Quantity': 0}, 'Comment': '', 'PriceClass': 'PriceClass_All', 'Enabled': True, 'ViewerCertificate': {'ACMCertificateArn': 'arn:aws:acm:us-east-1:123456789123:certificate/ccdd8a1d-831c-4bd2-9f94-95c8d17196df', 'SSLSupportMethod': 'sni-only', 'MinimumProtocolVersion': 'TLSv1.1_2016', 'Certificate': 'arn:aws:acm:us-east-1:123456789123:certificate/ccdd8a1d-831c-4bd2-9f94-95c8d17196df', 'CertificateSource': 'acm'}, 'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}}, 'WebACLId': '', 'HttpVersion': 'HTTP2', 'IsIPV6Enabled': True}]
        response = select_distribution('cdn1.dev.foobar.com.au', distributions)
        self.assertTrue(response)


def select_distribution(hostname, distributions):
    try:
        cloudfront_id = [x['Id'] for x in distributions if hostname in x['Aliases']['Items']][0]
    except:
        logging.exception(json.dumps({'action': 'check', 'status': 'failed', 'distributions': distributions}))
        return None
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
    logging.info(json.dumps({'invalidation': '{}'.format(invalidation['ResponseMetadata'])}))
    if invalidation['ResponseMetadata']['HTTPStatusCode'] == 201:
        response = "The invalidation for {} on distribution {} was successfully submitted.".format(path, cloudfront_id)
    else:
        response = "Didn't get a 201 response from CloudFront after submitting invalidation, something went wrong."
        logging.exception(json.dumps({'action': 'submitting invalidation', 'status': 'failed', 'invalidation': '{}'.format(invalidation['ResponseMetadata'])}))
    return response


def check_accounts_and_invalidate(accounts, hostname, path, correlation_id):
    cloudfront_id = None
    try:
        role = os.environ['BOT_AWS_ROLE']
    except KeyError:
        return "The role used to check each account hasn't been specified."
    for account in accounts:
        try:
            session = role_arn_to_session(
                RoleArn="arn:aws:iam::{}:role/{}".format(account, role),
                RoleSessionName=correlation_id)
        except:
            logging.exception(json.dumps({'action': 'assume role', 'status': 'failed', 'account': account, 'role': role}))
            pass  # probably okay to fail on an account or two
        else:
            logging.info(json.dumps({'action': 'assume role', 'status': 'success', 'account': account, 'role': role}))

        distributions = get_distributions(session, account)
        if distributions is not None:
            try:
                cloudfront_id = select_distribution(hostname, distributions)
            except:
                logging.info(json.dumps({"action": "check account", "account": account, "result": "failed"}))
                pass

            if cloudfront_id is not None:
                located_account = account
                logging.info(json.dumps({"action": "check account", "account": located_account, "result": "success"}))
                break

    if cloudfront_id is None:
        return "Could not find CloudFront distribution ID."

    try:
        response = invalidate_path(cloudfront_id, path, correlation_id, session)
    except:
        logging.exception(json.dumps({'action': 'invalidate path', 'status': 'failed', 'account': located_account, 'cloudfront_id': cloudfront_id, 'session': '{}'.format(session)}))
        return "Found CloudFront ID {} in account {} but the invalidation failed.".format(cloudfront_id, located_account)

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


def unit_test(event, context):
    result = []
    suite = unittest.TestLoader().loadTestsFromTestCase(post_message_tests)
    result.append(unittest.TextTestRunner().run(suite))
    suite = unittest.TestLoader().loadTestsFromTestCase(get_distributions_tests)
    result.append(unittest.TextTestRunner().run(suite))
    suite = unittest.TestLoader().loadTestsFromTestCase(select_distribution_tests)
    result.append(unittest.TextTestRunner().run(suite))
    return '{}'.format(result)
#    unittest.main(module=__name__)
#    unittest.main(module=__name__)
#    unittest.main()
