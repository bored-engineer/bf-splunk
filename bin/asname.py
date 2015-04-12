#!/usr/bin/env python

# Imports
import sys
import csv
import os
import socket
import netaddr

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

			# Get the IP address
			ip = netaddr.IPAddress(record[self.field])

			# Loop the entire cache, break when a ip is found
			found = None
			for i, net in enumerate(self.nets):
				if ip in net:
					found = self.asns[i]
					break

			# If we didn't find one, we need to look it up
			if found == None:

				# If we don't have a socket yet, make one and connect
				if self.s == None:

					# Create a new socket
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

				# Send the IP address followed by a newline
				self.s.send(record[self.field] + "\n")

				# Get the response from the socket
				found = next(self.r)
				self.logger.warn(str(found))

				# Store the prefix in the cache
				self.nets.append(netaddr.IPNetwork(found["ASPrefix"]))
				self.asns.append(found)

			self.logger.warn(str(asn))

			record["AS"] = self.asns[i]["AS"]

			# Yield the record
			yield record

		# Cleanup
		self.logger.warn("done")

	# Override the constructor
	def __init__(self):

		# Call the original
		super(StreamingCommand, self).__init__()

		# Cache holds all known networks
		self.nets = []
		self.asns = []

		# Hold the socket connection as needed
		self.s = None
		self.r = None

# Tell splunk we exist
dispatch(ASNameCommand, sys.argv, sys.stdin, sys.stdout, __name__)