import datetime
import hmac
import hashlib
import asyncio
from xml.etree.ElementTree import fromstring as parse_xml
from functools import partial
from urllib.parse import quote

import aiohttp


amz_uriencode = partial(quote, safe='~')
amz_uriencode_slash = partial(quote, safe='~/')
S3_NS = 'http://s3.amazonaws.com/doc/2006-03-01/'
NS = {'s3': S3_NS}


class Key(object):

    def __init__(self, *, key, last_modified, etag, size, storage_class):
        self.key = key
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.storage_class = storage_class

    @classmethod
    def from_xml(Key, el):
        return Key(
            key=el.find('s3:Key', namespaces=NS).text,
            last_modified=datetime.datetime.strptime(
                el.find('s3:LastModified', namespaces=NS).text,
                '%Y-%m-%dT%H:%M:%S.000Z'),
            etag=el.find('s3:ETag', namespaces=NS).text,
            size=int(el.find('s3:Size', namespaces=NS).text),
            storage_class=el.find('s3:StorageClass', namespaces=NS).text)

    def __repr__(self):
        return '<Key {}:{}>'.format(self.key, self.size)


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
    timestr = time.strftime('%a, %d %b %Y %H:%M:%S GMT')
    timestr = time.strftime("%Y%m%dT%H%M%SZ")
    req.headers['x-amz-date'] = timestr
    if isinstance(req.payload, bytes):
        payloadhash = hashlib.sha256(req.payload).hexdigest()
    else:
        payloadhash = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'
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
    def list(self, prefix='', max_keys=1000):
        result = yield from self._request(Request(
            "GET",
            "/",
            {'prefix': prefix,
             'max-keys': str(max_keys)},
            {'Host': self._host},
            b'',
            ))
        data = (yield from result.read())
        if result.status != 200:
            # TODO(tailhook) more fine-grained errors
            raise RuntimeError(data)
        x = parse_xml(data)
        if x.find('s3:IsTruncated', namespaces=NS).text != 'false':
            raise AssertionError(
                "File list is truncated, use bigger max_keys")
        return list(map(Key.from_xml,
                        x.findall('s3:Contents', namespaces=NS)))

    @asyncio.coroutine
    def download(self, key):
        if isinstance(key, Key):
            key = key.key
        result = yield from self._request(Request(
            "GET", '/' + key, {}, {'Host': self._host}, b''))
        if result.status != 200:
            # TODO(tailhook) more fine-grained errors
            raise RuntimeError((yield from result.read()))
        return result.content

    @asyncio.coroutine
    def upload(self, key, data):
        if isinstance(key, Key):
            key = key.key
        result = yield from self._request(Request(
            "PUT", '/' + key, {}, {'Host': self._host}, payload=data))
        if result.status != 200:
            # TODO(tailhook) more fine-grained errors
            raise RuntimeError((yield from result.read()))
        return result

    @asyncio.coroutine
    def get(self, key):
        if isinstance(key, Key):
            key = key.key
        result = yield from self._request(Request(
            "GET", '/' + key, {}, {'Host': self._host}, b''))
        if result.status != 200:
            # TODO(tailhook) more fine-grained errors
            raise RuntimeError((yield from result.read()))
        data = yield from result.read()
        return data

    @asyncio.coroutine
    def _request(self, req):
        sign(req, **self._aws_sign_data)
        return (yield from aiohttp.request(req.verb, req.url,
            chunked=not isinstance(req.payload, bytes),
            headers=req.headers,
            data=req.payload,
            connector=self._connector))
