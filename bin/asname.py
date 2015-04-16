#!/usr/bin/env python

# Imports
import sys
import csv
import os
import socket
import SubnetTree
import pickle
import os.path

# Search commands
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class ASNameCommand(StreamingCommand):

	# The field to use as a the IP to lookup
	field = Option(doc="", require=True, validate=validators.Fieldname())

	# Stream results as needed
	def stream(self, records):

		# As a record is passed in
		for record in records:

			# If the IP is not in the CIDR tree
			if record[self.field] not in self.tree:
				
				# If we don't have a socket yet
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
				result = next(self.r)
				
				# Clean it up
				prefix = result["ASPrefix"]
				self.prefixes.add(prefix)
				del result["ASPrefix"]
				del result[self.field]

				# Store the prefix in the tree
				self.tree[prefix] = result
				
			# Update the record with the values form the tree
			record.update(self.tree[record[self.field]])

			# Yield the record
			yield record
		
		# Write to the cache file
		with open("cidr_build.dat", 'w') as cache:
			pickle.dump({p: self.tree[p] for p in self.prefixes}, cache)

	# Override the constructor
	def __init__(self):

		# Call the original
		super(StreamingCommand, self).__init__()
		
		# Prefixes lists all known prefixs since subnet tree can't be pickled
		self.prefixes = set()

		# Tree holds the cidr ranges
		self.tree = SubnetTree.SubnetTree()

		# Read in from cache if it exists
		if os.path.isfile("cidr_build.dat"):
			with open("cidr_build.dat", 'r') as cache:
				treeDict = pickle.load(cache)
				self.prefixes = set(treeDict.keys())
				for p in self.prefixes:
					self.tree[p] = treeDict[p]

		# Hold the socket connection as needed
		self.s = None
		self.r = None
		

# Tell splunk we exist
dispatch(ASNameCommand, sys.argv, sys.stdin, sys.stdout, __name__)
