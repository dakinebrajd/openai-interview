"""Bounded, allowlisted public-source capture. Replay never invokes this module's fetcher."""

import argparse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .fixture_builder import FIXTURE_DIR
from .services import utc

RESEARCH_DIR = Path(__file__).resolve().parent.parent / 'fixtures' / 'enrichment' / 'v1'
ALLOWED = {'cveawg.mitre.org', 'www.cisa.gov', 'api.first.org', 'www.first.org',
           'logging.apache.org', 'openssl-library.org', 'curl.se', 'www.openssh.com',
           'www.openssh.org', 'msrc.microsoft.com', 'api.msrc.microsoft.com',
           'access.redhat.com', 'www.qualys.com', 'blog.qualys.com',
           'developers.openai.com', 'nvd.nist.gov'}


def validate_url(url):
    parsed = urlsplit(url)
    mirror = (parsed.hostname == 'raw.githubusercontent.com' and
              parsed.path == '/cisagov/kev-data/main/known_exploited_vulnerabilities.json')
    if (parsed.scheme != 'https' or (parsed.hostname not in ALLOWED and not mirror)
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError('URL is not an approved public HTTPS source')
    return url


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.ignored += 1

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self.ignored:
            self.ignored -= 1

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)


def source_text(source):
    body = source['body']
    if body.lstrip().lower().startswith(('<!doctype', '<html')):
        parser = TextExtractor()
        parser.feed(body)
        body = ' '.join(parser.parts)
    return ' '.join(body.split())


def fetch_source(source_id, url, kind, *, opener=None, sleep=time.sleep, attempts=3, now=None):
    """Capture actual attempts; retry transient errors only, never manufacture successful data."""
    validate_url(url)
    if not 1 <= attempts <= 3:
        raise ValueError('At most three attempts allowed')
    open_url = opener or build_opener(SafeRedirect()).open
    history = []
    for attempt in range(1, attempts+1):
        retrieved = now() if now else datetime.now(timezone.utc)
        entry = {'attempt': attempt, 'attempted_at': utc(retrieved)}
        try:
            request = Request(url, headers={'User-Agent': 'SyntheticVulnerabilityCaseStudy/1.0',
                                            'Accept': 'application/json,text/plain,text/html'})
            with open_url(request, timeout=15) as response:
                final_url = response.geturl()
                validate_url(final_url)
                data = response.read(8_000_001)
                if len(data) > 8_000_000:
                    raise ValueError('Source exceeds 8 MB limit')
                body = data.decode('utf-8')
            entry['outcome'] = 'Success'
            history.append(entry)
            days = 1 if kind in ('KEV', 'EPSS') else 30
            return dict(id=source_id, url=url, final_url=final_url, kind=kind, fetch_status='Success',
                retrieved_at=utc(retrieved), expires_at=utc(retrieved+timedelta(days=days)),
                content_sha256=sha256(data).hexdigest(), body=body, attempts=history, error=None,
                confidence='primary_source', published_at=None)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
            code = getattr(error, 'code', None)
            entry.update(outcome='Failed', error=str(error), http_status=code)
            history.append(entry)
            retryable = code in (429, 500, 502, 503, 504) or isinstance(error, (URLError, TimeoutError, OSError)) and code is None
            if not retryable or attempt == attempts:
                return dict(id=source_id, url=url, final_url=url, kind=kind, fetch_status='Failed',
                    retrieved_at=utc(retrieved), expires_at=utc(retrieved), content_sha256=None,
                    body='', attempts=history, error=str(error), confidence='unavailable', published_at=None)
            sleep(min(2**(attempt-1), 4))


def source_requests():
    catalog = json.loads((FIXTURE_DIR/'cve_sources.json').read_text(encoding='utf-8'))
    cves = [r['cve_id'] for r in catalog['records']]
    requests = [(cve, f'https://cveawg.mitre.org/api/cve/{cve}', 'CVE') for cve in cves]
    requests += [
        ('kev-cisa', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'KEV'),
        ('kev-mirror', 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json', 'KEV'),
        ('epss', 'https://api.first.org/data/v1/epss?cve='+','.join(cves), 'EPSS'),
        ('apache', 'https://logging.apache.org/security.html', 'Vendor'),
        ('openssl', 'https://openssl-library.org/news/secadv/20221101.txt', 'Vendor'),
        ('curl', 'https://curl.se/docs/CVE-2023-38545.html', 'Vendor'),
        ('openssh-98', 'https://www.openssh.com/txt/release-9.8', 'Vendor'),
        ('openssh-93p2', 'https://www.openssh.com/txt/release-9.3p2', 'Vendor'),
        ('msrc-outlook', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397', 'Vendor'),
        ('msrc-print', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527', 'Vendor'),
        ('redhat-pkexec', 'https://access.redhat.com/security/cve/CVE-2021-4034', 'Vendor'),
        ('sector-log4j', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-174a', 'Sector'),
        ('sdk-docs', 'https://developers.openai.com/api/docs/guides/agents/define-agents?lang=python', 'SDK'),
    ]
    return requests


def capture(directory=RESEARCH_DIR):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for id, url, kind in source_requests():
        path = directory / (id+'.json')
        if path.exists():
            raise ValueError(f'Refusing to overwrite versioned snapshot {path}; use a new capture directory')
        record = fetch_source(id, url, kind)
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
        print(id, record['fetch_status'], len(record['body']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=RESEARCH_DIR)
    capture(parser.parse_args().output_dir)
