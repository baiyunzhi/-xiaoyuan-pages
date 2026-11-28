"""Bounded encrypted transport of unchanged Yahoo responses; no price calculations."""
from datetime import datetime, timedelta, timezone
from io import BytesIO
import base64
import gzip
import hashlib
import json
import subprocess

RAW_SCHEMA = 'xiaoyuan.mnq.yahoo-raw.v1'
CMS_SCHEMA = 'xiaoyuan.mnq.encrypted-packet.v1'
RANGES = {'1m':'7d', '5m':'30d', '1h':'60d', '1d':'2y', '1wk':'5y'}
MAX_SOURCE = 2*1024**2
MAX_PLAIN = 16*1024**2
MAX_CIPHER = 20*1024**2


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('non-finite JSON constant')


def loads(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('invalid packet JSON') from error


def utc(value):
    try:
        stamp = datetime.fromisoformat(value.replace('Z','+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('timezone required')
        return stamp.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError('invalid aware capture time') from error


def validate_source(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_SOURCE:
        raise ValueError('Yahoo response size invalid')
    try:
        body = loads(raw)
        chart = body['chart']
        records = chart['result']
        if chart.get('error') is not None or not isinstance(records,list) or len(records) != 1:
            raise ValueError('Yahoo result invalid')
        result = records[0]
        if result['meta']['symbol'] != 'MNQ=F' or result['meta']['exchangeTimezoneName'] != 'America/New_York':
            raise ValueError('Yahoo instrument or timezone changed')
        times = result['timestamp']
        quotes = result['indicators']['quote']
        if not isinstance(times,list) or not times or not isinstance(quotes,list) or len(quotes) != 1:
            raise ValueError('Yahoo arrays invalid')
        if any(not isinstance(quotes[0][key],list) or len(quotes[0][key]) != len(times)
               for key in ('open','high','low','close','volume')):
            raise ValueError('Yahoo array lengths invalid')
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError('Yahoo response format invalid') from error


def make(raws, captured_at):
    if set(raws) != set(RANGES):
        raise ValueError('all five native intervals required')
    utc(captured_at)
    for raw in raws.values():
        validate_source(raw)
    return dict(schema=RAW_SCHEMA, symbol='MNQ=F', captured_at=captured_at,
                intervals={key:base64.b64encode(raws[key]).decode('ascii') for key in RANGES})


def unpack(body, now=None):
    if (not isinstance(body,dict) or set(body) != {'schema','symbol','captured_at','intervals'}
            or body['schema'] != RAW_SCHEMA or body['symbol'] != 'MNQ=F'
            or not isinstance(body['intervals'],dict) or set(body['intervals']) != set(RANGES)):
        raise ValueError('raw packet schema or intervals invalid')
    captured = utc(body['captured_at'])
    age = (now or datetime.now(timezone.utc))-captured
    if not timedelta(0) <= age <= timedelta(minutes=30):
        raise ValueError('packet stale or future')
    raws = {}
    for key,value in body['intervals'].items():
        if not isinstance(value,str) or len(value) > 4*((MAX_SOURCE+2)//3):
            raise ValueError('encoded Yahoo response size invalid')
        try:
            raw = base64.b64decode(value,validate=True)
        except (ValueError, UnicodeError) as error:
            raise ValueError('Yahoo response encoding invalid') from error
        validate_source(raw)
        raws[key] = raw
    return captured, raws


def _openssl(args, raw, executable):
    result = subprocess.run([str(executable),'cms',*args],input=raw,capture_output=True,timeout=30)
    if result.returncode:
        raise ValueError('CMS operation failed: '+result.stderr.decode('utf-8',errors='replace')[-400:])
    return result.stdout


def encrypt(body, certificate, executable='openssl'):
    certificate = str(certificate)
    from pathlib import Path
    pem = Path(certificate).read_bytes()
    if b'BEGIN CERTIFICATE' not in pem or b'PRIVATE KEY' in pem:
        raise ValueError('worker accepts a public PEM certificate only')
    raw = json.dumps(body,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    if not 0 < len(raw) <= MAX_PLAIN:
        raise ValueError('raw packet size invalid')
    encrypted = _openssl(['-encrypt','-binary','-outform','DER','-aes256','-recip',certificate,
                          '-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],
                         gzip.compress(raw,compresslevel=6,mtime=0),executable)
    if not 0 < len(encrypted) <= MAX_CIPHER:
        raise ValueError('ciphertext size invalid')
    manifest = dict(schema=CMS_SCHEMA,captured_at=body['captured_at'],
                    ciphertext_sha256=hashlib.sha256(encrypted).hexdigest(),ciphertext_bytes=len(encrypted))
    return encrypted,manifest


def decrypt(encrypted, manifest, certificate, key, *, executable='openssl', now=None):
    if (not isinstance(manifest,dict) or set(manifest) != {'schema','captured_at','ciphertext_sha256','ciphertext_bytes'}
            or manifest['schema'] != CMS_SCHEMA or type(manifest['ciphertext_bytes']) is not int
            or not 0 < len(encrypted) <= MAX_CIPHER or len(encrypted) != manifest['ciphertext_bytes']
            or hashlib.sha256(encrypted).hexdigest() != manifest['ciphertext_sha256']):
        raise ValueError('encrypted packet hash, size or schema invalid')
    compressed = _openssl(['-decrypt','-binary','-inform','DER','-recip',str(certificate),'-inkey',str(key)],
                          encrypted,executable)
    try:
        with gzip.GzipFile(fileobj=BytesIO(compressed)) as stream:
            raw = stream.read(MAX_PLAIN+1)
    except (OSError, EOFError) as error:
        raise ValueError('compressed packet invalid') from error
    if not 0 < len(raw) <= MAX_PLAIN:
        raise ValueError('decompressed packet size invalid')
    body = loads(raw)
    captured,raws = unpack(body,now)
    if body['captured_at'] != manifest['captured_at']:
        raise ValueError('capture time differs from encrypted content')
    return captured,raws
