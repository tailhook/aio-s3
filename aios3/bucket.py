import datetime
import hmac
import hashlib
import asyncio
from functools import partial
from urllib.parse import quote

import aiohttp


amz_uriencode = partial(quote, safe='~')
amz_uriencode_slash = partial(quote, safe='~/')


class Request(object):
    def __init__(self, verb, resource, query, headers, payload):
        self.verb = verb
        self.resource = amz_uriencode_slash(resource)
        self.query_string = '&'.join(
            k + '=' + v
            for k, v in sorted((amz_uriencode(k), amz_uriencode(v))
                               for k, v in query.items()))
        self.headers = headers
        self.payload = payload

    @property
    def url(self):
        return 'http://{0.headers[Host]}{0.resource}?{0.query_string}'\
            .format(self)


def _hmac(key, val):
    return hmac.new(key, val, hashlib.sha256).digest()


def _signkey(key, date, region, service):
    date_key = _hmac(("AWS4" + key).encode('ascii'),
                        date.encode('ascii'))
    date_region_key = _hmac(date_key, region.encode('ascii'))
    svc_key = _hmac(date_region_key, service.encode('ascii'))
    return _hmac(svc_key, b'aws4_request')


def sign(req, *,
         aws_key, aws_secret, aws_service='s3', aws_region='us-east-1'):

    time = datetime.datetime.utcnow()
    date = time.strftime('%Y%m%d')
    payloadhash = hashlib.sha256(req.payload).hexdigest()
    timestr = time.strftime('%a, %d %b %Y %H:%M:%S GMT')
    timestr = time.strftime("%Y%m%dT%H%M%SZ")
    req.headers['x-amz-date'] = timestr
    req.headers['x-amz-content-sha256'] = payloadhash

    signing_key = _signkey(aws_secret, date, aws_region, aws_service)

    headernames = ';'.join(k.lower() for k in sorted(req.headers))

    creq = (
        "{req.verb}\n"
        "{req.resource}\n"
        "{req.query_string}\n"
        "{headers}\n\n"
        "{headernames}\n"
        "{payloadhash}".format(
        req=req,
        headers='\n'.join(k.lower() + ':' + req.headers[k].strip()
            for k in sorted(req.headers)),
        headernames=headernames,
        payloadhash=payloadhash
        ))
    string_to_sign = (
        "AWS4-HMAC-SHA256\n{ts}\n"
        "{date}/{region}/{service}/aws4_request\n"
        "{reqhash}".format(
        ts=timestr,
        date=date,
        region=aws_region,
        service=aws_service,
        reqhash=hashlib.sha256(creq.encode('ascii')).hexdigest(),
        ))
    sig = hmac.new(signing_key, string_to_sign.encode('ascii'),
        hashlib.sha256).hexdigest()

    ahdr = ('AWS4-HMAC-SHA256 '
        'Credential={key}/{date}/{region}/{service}/aws4_request, '
        'SignedHeaders={headers}, Signature={sig}'.format(
        key=aws_key, date=date, region=aws_region, service=aws_service,
        headers=headernames,
        sig=sig,
        ))
    req.headers['Authorization'] = ahdr


class Bucket(object):

    def __init__(self, name, *,
                 aws_key, aws_secret,
                 aws_region='us-east-1',
                 aws_endpoint='s3.amazonaws.com',
                 connector=None):
        self._name = name
        self._connector = None
        self._aws_sign_data = {
            'aws_key': aws_key,
            'aws_secret': aws_secret,
            'aws_region': aws_region,
            'aws_service': 's3',
            }
        self._host = self._name + '.' + aws_endpoint

    @asyncio.coroutine
    def list(self, prefix='', delimiter='', max_keys=1000):
        result = yield from self._request(Request(
            "GET",
            "/",
            {'prefix': prefix,
             'delimiter': delimiter,
             'max-keys': str(max_keys)},
            {'Host': self._host},
            b'',
            ))
        print("RESULT", result, (yield from result.read()))

    @asyncio.coroutine
    def _request(self, req):
        sign(req, **self._aws_sign_data)
        return (yield from aiohttp.request(req.verb, req.url,
            headers=req.headers,
            data=req.payload,
            connector=self._connector))
