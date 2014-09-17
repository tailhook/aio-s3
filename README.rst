===================
Asyncio S3 Bindings
===================

:Status: Alpha

The `aio-s3` is a small library for accessing Amazon S3 Service that leverages
python's standard `asyncio` library.

Only read operations are supported so far, contributions are welcome.


Example
=======

Basically all methods supported so far are shown in this example:

.. code-block:: yaml

    import asyncio

    from aios3.bucket import Bucket


    @asyncio.coroutine
    def main():
        bucket = Bucket('uaprom-logs',
            aws_region='eu-west-1',
            aws_endpoint='s3-eu-west-1.amazonaws.com',
            aws_key='AKIAIOSFODNN7EXAMPLE',
            aws_secret='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
        # List keys based on prefix
        lst = yield from bu.list('some-prefix')
        response = yield from bu.get(lst[0])
        print(len(response))
        response = yield from bu.download(lst[0])
        print("GOT Response", dir(response))
        while 1:
            chunk = yield from response.read(65536)
            print("Received", len(chunk))
            if not chunk:
                break

    asyncio.get_event_loop().run_until_complete(main())


Reference
=========

``Bucket(name, *, aws_key, aws_secret, aws_region, aws_endpoint, connector)``:
    Creates a wrapper object for accessing S3 bucket. Note unlike in many
    other bindings you need to specify aws_region (and probably aws_endpoint)
    correctly (see a table_). The ``connector`` is an aiohttp_ connector,
    which might be used to setup proxy or other useful things.

``Bucket.list(prefix='', max_keys=1000)``:
    Lists items which start with prefix. Each returned item is a ``Key``
    object. This method is coroutine.

    .. note:: This method raises assertion error if there are more keys than
       max_keys. We do not have a method to return keys iteratively yet.

``Bucket.get(key)``:
    Fetches object names ``key``. The ``key`` might be a string or ``Key``
    object. Returns bytes. This method is coroutine.

``Bucket.download(key)``:
    Allows iteratively download the ``key``. The object returned by the
    coroutine is an object having method ``.read(bufsize)`` which is a
    coroutine too.

``Key``
    Represents an S3 key returned by ``Bucket.list``. Key has at least the
    following attributes:

    * ``key`` -- the full name of the key stored in a bucket
    * ``last_modified`` -- ``datetime.datetime`` object
    * ``etag`` -- The ETag, usually md5 of the content with additional quotes
    * ``size`` -- Size of the object in bytes
    * ``storage_class`` -- Storage class of the object


.. _table: http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
.. _aiohttp: http://aiohttp.readthedocs.org


