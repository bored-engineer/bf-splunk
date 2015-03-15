#!/usr/bin/env python

# Imports
import sys
import csv
import re
import os

# Search commands
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class BrowscapCommand(StreamingCommand):

    # The field to use as a userAgent
    field = Option(doc="", require=True, validate=validators.Fieldname())

    # If we are to use liteMode
    liteMode = Option(doc="", require=False, validate=validators.Boolean())

    # Stream results as needed
    def stream(self, records):

        # As a record is passed in
        for record in records:

            # Get the matching rows for that userAgent
            matches = [row for i, row in enumerate(self.row_cache) if self.regex_cache[i].match(record[self.field])]

            # Get the longest regex as it's probably the most accurate, or if none found, use defaults
            match = max(matches, key=lambda row:len(row["PropertyName"])) if len(matches) > 0 else self.defaults

            # Add all the fields we know about to the results
            for key, value in match.iteritems():

                # Save the value from the match onto the record
                record["UA_" + key] = value

            # Yield the record
            yield record

    # Override the constructor
    def __init__(self):

        # Call the original
        super(StreamingCommand, self).__init__()

        # Hold the compiled regex and rows
        self.regex_cache = []
        self.row_cache = []

        # Hold the defaults
        self.defaults = []

        # Read in the browscap csv
        with open(os.path.join(os.path.dirname(__file__), "browscap.csv"), "rb") as browscap_file:

            # Read the first two garbage lines and ignore them
            browscap_file.readline()
            browscap_file.readline()

            # Read the rest as a csv
            browscap = csv.DictReader(browscap_file)

            # Hold the default values
            self.defaults = next(browscap)

            # Loop each row in browsercap
            for row in browscap:

                # If it's a MasterParent, ignore it, it's useless
                if row["MasterParent"] == "true":
                    continue

                # If liteMode is enabled and it's not a liteMode rule, ignore it
                if self.liteMode and row["LiteMode"] != "true":
                    continue

                # Compile the expression
                ua_regex = '^{0}$'.format(re.escape(row["PropertyName"]))
                ua_regex = ua_regex.replace('\\?', '.').replace('\\*', '.*?')
                self.regex_cache.append(re.compile(ua_regex))

                # Save it in the cache as well
                self.row_cache.append(row)

# Tell splunk we exist
dispatch(BrowscapCommand, sys.argv, sys.stdin, sys.stdout, __name__)