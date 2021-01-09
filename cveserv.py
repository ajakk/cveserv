#!/usr/bin/env python

from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Event, Lock, Thread
import argparse
import gzip
import io
import os.path
import sys
import time

import requests
import pandas


def tprint(string):
    print("[{}] {}".format(datetime.now(), string))


class CVEdb():
    BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{when}.{ext}"
    JSON_GZ = BASE_URL.format(when="{when}", ext="json.gz")
    MODIFIED_META = BASE_URL.format(when="modified", ext="meta")
    MODIFIED_JSON_GZ = JSON_GZ.format(when="modified")

    # Some strings to ease slicing the dataframes
    CVE_DESC = "cve.description.description_data"
    CVE_ITEMS = "CVE_Items"
    CVE_NUM = "CVE_data_numberOfCVEs"
    CVE_ID = "cve.CVE_data_meta.ID"

    last_modified = None

    def __init__(self, dbfile, lock, update_delay):
        self.cve_df = pandas.DataFrame()
        self.lock = lock
        self.dbfile = dbfile
        self.update_delay = update_delay

        if os.path.exists(dbfile) and os.path.isfile(dbfile):
            tprint("Reading pickle")
            self.cve_df = pandas.read_pickle(dbfile)
        elif os.path.isdir(dbfile):
            tprint("Cannot use a directory as dbfile")
            sys.exit(-1)
        else:
            tprint("First run, will fetch all data")
            self._first_fetch()

    @staticmethod
    def _gz_data(gz_file):
        with gzip.open(gz_file, 'rb') as data:
            return data.read()

    @staticmethod
    def _get_urldata(url):
        return requests.get(url).content

    def _first_fetch(self):
        for year in range(2002, datetime.now().year + 1):
            tprint("Fetching year {}".format(year))

            urldata = self._get_urldata(self.JSON_GZ.format(when=year))
            gz_string = self._gz_data(io.BytesIO(urldata))

            self.update_from_json(io.BytesIO(gz_string), merge=False)

    @staticmethod
    def _categorize(frame):
        cols = ['CVE_data_type', 'CVE_data_format', 'CVE_data_version',
                'CVE_data_timestamp', 'cve.data_type', 'cve.data_format',
                'cve.data_version', 'cve.CVE_data_meta.ASSIGNER',
                'configurations.CVE_data_version',
                'impact.baseMetricV2.cvssV2.version',
                'impact.baseMetricV2.cvssV2.vectorString',
                'impact.baseMetricV2.cvssV2.accessVector',
                'impact.baseMetricV2.cvssV2.accessComplexity',
                'impact.baseMetricV2.cvssV2.authentication',
                'impact.baseMetricV2.cvssV2.confidentialityImpact',
                'impact.baseMetricV2.cvssV2.integrityImpact',
                'impact.baseMetricV2.cvssV2.availabilityImpact',
                'impact.baseMetricV2.cvssV2.baseScore',
                'impact.baseMetricV2.severity',
                'impact.baseMetricV2.exploitabilityScore',
                'impact.baseMetricV2.impactScore',
                'impact.baseMetricV2.obtainAllPrivilege',
                'impact.baseMetricV2.obtainUserPrivilege',
                'impact.baseMetricV2.obtainOtherPrivilege',
                'impact.baseMetricV2.userInteractionRequired',
                'impact.baseMetricV3.cvssV3.version',
                'impact.baseMetricV3.cvssV3.vectorString',
                'impact.baseMetricV3.cvssV3.attackVector',
                'impact.baseMetricV3.cvssV3.attackComplexity',
                'impact.baseMetricV3.cvssV3.privilegesRequired',
                'impact.baseMetricV3.cvssV3.userInteraction',
                'impact.baseMetricV3.cvssV3.scope',
                'impact.baseMetricV3.cvssV3.confidentialityImpact',
                'impact.baseMetricV3.cvssV3.integrityImpact',
                'impact.baseMetricV3.cvssV3.availabilityImpact',
                'impact.baseMetricV3.cvssV3.baseScore',
                'impact.baseMetricV3.cvssV3.baseSeverity',
                'impact.baseMetricV3.exploitabilityScore',
                'impact.baseMetricV3.impactScore',
                'impact.baseMetricV2.acInsufInfo',
                'lang']

        # Use categorical types for certain columns for less memory usage
        for col in cols:
            try:
                frame[col] = pandas.Categorical(frame[col])
            except KeyError:
                # Certain fields will only be full if the CVE has been
                # analyzed, like impact fields. Only raise the error if not on
                # one of those columns.
                if not col.startswith('impact'):
                    raise

    def update_from_json(self, data, merge=True):
        """
        Updates CVE database given input json data
        """

        # The data comes out in a few columns, only two of which appear to
        # somewhat useful - CVE_data_timestamp and CVE_Items. Unfortunately
        # read_json will produce a CVE_Items column of nested JSON data so we
        # will convert the column into its own dataframe then join it
        # to the side of the original
        frame = pandas.read_json(data)
        frame = frame.join(pandas.json_normalize(frame[self.CVE_ITEMS]))

        # Since the data is now stored elsewhere we can safely delete the
        # column to save memory
        del frame[self.CVE_ITEMS]

        # Since NIST distributes chunks of CVEs in yearly and modified formats,
        # this would contain the number of CVEs in whichever chunk was
        # distributed. We aggregate everything into one structure, so it's
        # useless.
        del frame[self.CVE_NUM]

        # This description column is strangely full of single-element JSON
        # lists, and pandas won't normalize JSON arrays:
        # https://github.com/pandas-dev/pandas/issues/21608
        #
        # We can solve this by just converting the column of lists to the
        # lists' first values before trying to normalize. Unfortunately given
        # each list item has a 'lang' key so this might indicate this array has
        # descriptions in multiple languages, but it also seems to use list
        # items instead of newlines. The schema isn't clear on this:
        #
        # https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
        #
        # FIXME: We'll just use the first one for now.
        frame[self.CVE_DESC] = frame[self.CVE_DESC].transform(lambda x: x[0])
        frame = frame.join(pandas.json_normalize(frame[self.CVE_DESC]))

        # As before, safe to delete
        del frame[self.CVE_DESC]

        # At last categorize columns for memory
        self._categorize(frame)

        # TODO: The dataframes can be optimized for memory quite a bit
        # TODO: At some point data with slashes in them get escaped, / -> \/.
        # This is undesirable.

        # And then we add it to the running class dataframe or replace the
        # empty one created as a placeholder
        if self.cve_df.empty:
            self.cve_df = frame
        else:
            start_time = time.time()
            if merge:
                self.cve_df = self.cve_df.append(frame, ignore_index=True)
                self.cve_df = self.cve_df.drop_duplicates(
                        subset='cve.CVE_data_meta.ID', keep='last')
            else:
                self.cve_df = self.cve_df.append(frame, ignore_index=True)
            tprint("That took {} seconds".format(time.time() - start_time))

        # TODO: Would be nice to know how many are added/modified here, too
        tprint("CVE db now at length {} after adding {} CVEs".format(
            len(self.cve_df.index), len(frame.index)))

    def _update(self):
        tprint("Attempting to update db")

        # The modified feed has a metadata file with a timestamp that we check
        # to see if the modified feed has been modified since the last time we
        # fetched it
        modified_meta = self._get_urldata(self.MODIFIED_META)

        # Pull the ISO8601 date string out of that file
        firstline = modified_meta.splitlines()[0].decode()
        isostring = firstline.replace("lastModifiedDate:", "")

        # And create a datetime object of it
        modified_at = datetime.fromisoformat(isostring)

        if self.last_modified is None:
            tprint("Haven't fetched the modified feed yet, "
                   "fetching and updating...")
        elif self.last_modified < modified_at:
            tprint("Modified feed has been updated since last fetch, "
                   "updating...")
        elif self.last_modified == modified_at:
            tprint("Modified feed not updated since last fetch")
            return
        else:  # For completeness
            tprint("The sky is falling!")

        self.last_modified = modified_at

        urlfile = io.BytesIO(self._get_urldata(self.MODIFIED_JSON_GZ))

        # TODO: this can probably be done quicker by creating a copy of the
        # dataframe and then setting self.cve_df to it later (and thus
        # minimizing downtime of the HTTP server due to locking. Can't test
        # right away due to memory considerations
        self.lock.acquire()
        self.update_from_json(self._gz_data(urlfile))
        self.lock.release()

    def update_loop(self, event):
        while True:
            when = datetime.now()
            self._update()
            self.save()
            # This probably isn't as good at avoiding skew as it could be
            if (event.wait(self.update_delay -
                           (datetime.now() - when).total_seconds())):
                # event.wait returns true IFF flag is true with event.set()
                # Here, that means we need to exit
                return

    def get_cve_json(self, cve):
        self.lock.acquire()
        row = self.cve_df[self.cve_df[self.CVE_ID] == cve]
        data_json = row.to_json()
        self.lock.release()
        return data_json

    def save(self):
        tprint("Saving pickle to {}".format(self.dbfile))
        self.cve_df.to_pickle(self.dbfile)


class CVEHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        cvedb = self.server.cvedb
        cve = self.path.replace("/", "")
        json_data = cvedb.get_cve_json(cve)
        self.wfile.write(json_data.encode('utf-8'))


class CVEHTTPServer(HTTPServer):
    def __init__(self, cvedb, *args, **kwargs):
        self.cvedb = cvedb
        super().__init__(*args, **kwargs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dbfile", help="Set DB path",
                        default="./cvedb.bz2")
    parser.add_argument("--delay", default=3600, type=int)
    args = parser.parse_args()

    # NIST doesn't want people making more than 200 requests a day. There's a
    # maximum of two requests per update (the meta and actual data), 200/2 =
    # 100, we will try to make sure we do not update more than 100 times per
    # day. This is a more than reasonable update period anyway.
    times_per_day = (60*60*24/args.delay)

    if times_per_day > 100:
        tprint("Refusing to send more than 200 requests per day.")
        tprint("Maximum requests per day with period of {} seconds: {}".format(
            args.delay, int(times_per_day)))
        tprint("https://nvd.nist.gov/vuln/data-feeds")
        sys.exit(-1)

    tprint("Will update ~{} times per hour".format((60*60)/args.delay))

    cvedb = CVEdb(args.dbfile, Lock(), args.delay)
    e = Event()
    updateProcess = Thread(target=cvedb.update_loop, args=(e,))
    updateProcess.start()

    tprint("Starting http server")
    httpd = CVEHTTPServer(cvedb, ('127.0.0.1', 8000), CVEHTTPRequestHandler)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        e.set()
        tprint("Interrupt recieved, exiting")
    updateProcess.join()

    cvedb.save()

    tprint("Done")
