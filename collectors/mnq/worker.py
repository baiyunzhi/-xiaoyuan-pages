"""Hosted acquisition: original Yahoo JSON in, encrypted ciphertext only out."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import importlib.metadata
import json
import os
import tempfile
import time

import packet


def fetch(period):
    if importlib.metadata.version('curl_cffi') != '0.15.0':
        raise RuntimeError('worker requires reviewed curl_cffi0.15.0')
    from curl_cffi import requests
    for attempt,host in enumerate(('query1','query2','query1')):
        try:
            response = requests.get(f'https://{host}.finance.yahoo.com/v8/finance/chart/MNQ%3DF?range={packet.RANGES[period]}&interval={period}',
                                    impersonate='chrome',timeout=45)
        except requests.RequestsError as error:
            if attempt == 2:
                raise RuntimeError('Yahoo transport failed for '+period+': '+type(error).__name__) from None
        else:
            if response.status_code == 200:
                raw = response.content
                packet.validate_source(raw)
                return raw
            if response.status_code not in {403,408,429,500,502,503,504} or attempt == 2:
                raise RuntimeError('Yahoo HTTP'+str(response.status_code)+' for '+period)
        time.sleep(2**attempt)


def acquire(certificate, output, *, fetcher=fetch, clock=lambda: datetime.now(timezone.utc), executable='openssl'):
    moment = clock()
    if moment.tzinfo is None:
        raise ValueError('aware capture clock required')
    captured_at = moment.astimezone(timezone.utc).isoformat()
    raws = {period:fetcher(period) for period in packet.RANGES}
    encrypted,manifest = packet.encrypt(packet.make(raws,captured_at),certificate,executable)
    output = Path(output)
    output.mkdir(parents=True,exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('wb',dir=output,delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary,0o600)
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,output/'packet.cms')
        (output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return manifest


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--certificate',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--openssl',default='openssl')
    args=parser.parse_args(argv)
    try:
        manifest=acquire(args.certificate,args.output,executable=args.openssl)
        print(json.dumps(manifest))
        return 0
    except Exception as error:
        print(json.dumps(dict(status='failed',error_type=type(error).__name__,error=str(error)[:600])))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
