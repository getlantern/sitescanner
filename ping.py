#!/usr/bin/env python

"""
Try the IPs for all domains in the given file (which is in the format output
by sitescanner), save reachability and timing info to a yaml file.
"""

from datetime import datetime
import itertools
import os
import re
import socket
from urlparse import urlparse
import time
import traceback

import requests
import yaml


target_url = 'www.cloudflare.com'
title_re = re.compile('<title>.*</title>')
expected_title = u'<title>Home | CloudFlare | The web performance &amp; security company</title>'


def main(infile, outfile):
    times = {}
    for domain in domains_from_scanner_output(open(infile).read()):
        # Prefer the first domain with any given IP, since that has the higher
        # Alexa ranking.
        times.setdefault(socket.gethostbyname(domain),
                         {'domain': domain, 'times': []})
    bad_ips = set()
    for batch in itertools.count(1):
        print datetime.utcnow().isoformat(), "Starting batch %s..." % batch
        start = time.time()
        for ip, d in times.iteritems():
            try:
                d['times'].append(response_time(ip))
            except BadFront:
                bad_ips.add(ip)
        # Make write atomic.
        tmpfile = outfile + '.tmp'
        yaml.dump({'times': times, 'bad_ips': list(bad_ips)},
                  file(tmpfile, 'w'))
        os.rename(tmpfile, outfile)
        seconds = time.time() - start
        minutes = seconds // 60
        hours = minutes // 60
        print "Batch took",
        if hours:
            print hours, "hours,",
        if minutes:
            print minutes, "minutes,",
        print int(seconds), "seconds."

class BadFront(Exception):
    pass

def response_time(ip):
    start = time.time()
    # If you want to test with TLS, s/http/https/ and add a verify=False argument.
    try:
        response = requests.get('http://%s/' % ip,
                                headers={'Host': target_url})
    except requests.exceptions.RequestException:
        print "request exception!"
        traceback.print_exc()
        raise BadFront
    if not response.ok:
        print "response not ok!"
        raise BadFront
    match = re.search(title_re, response.text)
    if match is None or match.group() != expected_title:
        print "bad match!", match and match.group()
        raise BadFront
    return time.time() - start

def domains_from_scanner_output(s):
    return [urlparse(line.split()[-1]).netloc
            for line in s.split("\n")[3:]
            if line.strip()]

if __name__ == '__main__':
    main('top-cloudflare-fronts-with-ip.txt',
         'out.yaml')
