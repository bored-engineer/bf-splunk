#!/usr/bin/env python

# Imports
import sys
import csv
import os
import socket

# Search commands
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class ASNameCommand(StreamingCommand):

	# The field to use as a the IP to lookup
	field = Option(doc="", require=True, validate=validators.Fieldname())

	# Stream results as needed
	def stream(self, records):
		self.logger.warn("setup")

		# As a record is passed in
		for record in records:
			self.logger.warn(str(record))

			# If we have a cache of this record
			if record[self.field] in self.cache:

				# Use it
				result = self.cache[record[self.field]]

			# Request a lookup
			else:

				# Send the IP address followed by a newline
				self.s.send(record[self.field] + "\n")

				# Get the response from the socket
				result = next(self.r)
				self.logger.warn(str(result))

				# Save it in the cache
				self.cache[record[self.field]] = result

			# Write the key value back into the record
			for key, value in result.iteritems():
				if key != None:
					record[key] = value

			# Yield the record
			yield record

	# Override the constructor
	def __init__(self):

		# Call the original
		super(StreamingCommand, self).__init__()

		# Cache results
		self.cache = {}

		# Hold the socket connection
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# Connect to Team Cymru (https://www.team-cymru.org/IP-ASN-mapping.html)
		self.s.connect(("whois.cymru.com", 43))

		# Send the header
		self.s.send("begin\nverbose\n")

		# Make s into a file for ease of use
		f = self.s.makefile()

		# Read in the header and ignore it
		self.logger.warn(f.readline())

		# Use a DictReader to process the "file"
		self.r = csv.DictReader(f,
			delimiter='|',
			quoting=csv.QUOTE_NONE,
			skipinitialspace=True,
			fieldnames=["AS", self.field, "ASPrefix", "ASCountry", "ASRegistry", "ASAllocDate", "ASName"]
		)

# Tell splunk we exist
dispatch(ASNameCommand, sys.argv, sys.stdin, sys.stdout, __name__)