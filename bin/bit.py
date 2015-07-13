#!/usr/bin/env python

# Imports
import sys
import csv
import os

# Search commands
from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators

# Identify the bit where a difference in characters first occurs in two strings
def findBit(str1, str2):

	# Loop each character in str1 and str2
	for i, (c1, c2) in enumerate(zip(str1, str2)):

		# If it's different, we found our flipped character
		if c1 != c2:

			# Identify the bit where the flip occured
			return '{:08b}'.format(ord(c1) ^ ord(c2)).index('1')

	# Return not found
	return -1  

class BitCommand(ReportingCommand):

	# Reduce the results to a nice result set
	def reduce(self, records):
		
		# Store an object for each qNameUnflipped and within it the bits
		flips = {}
		probs = {}

		# Get the path to the lookup file
		lookup_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lookups", "bf_dns_qName.csv")

		# Open the lookup for reading
		with open(lookup_path) as f:

			# Parse it using a DictReader
			lookup = csv.DictReader(f)

			# For each row in the lookups
			for row in lookup:

				# Add the key if needed to both probs and flips
				if row["qNameUnflipped"] not in probs:
					probs[row["qNameUnflipped"]] = [0, 0, 0, 0, 0, 0, 0, 0]
					flips[row["qNameUnflipped"]] = [0, 0, 0, 0, 0, 0, 0, 0]

				# Lookup the bit where the error occured and increment the count for it
				probs[row["qNameUnflipped"]][findBit(row["qName"][1:], row["qNameUnflipped"])] += 1

		# Loop each record
		for record in records:

			# Identify which bit the flip occured in and increment that count for the given qNameUnflipped
			flips[record["qNameUnflipped"]][findBit(record["qNameUnflipped"], record["domain"])] += int(record["count"])

		# Loop each flips for the reporting
		for qNameUnflipped, bits in flips:

			# Loop each bit for the qNameUnflipped
			for i, count in bits:

				# Yield a record
				yield { qNameUnflipped: qNameUnflipped, bit: i, count: count/probs[qNameUnflipped][i] }

# Tell splunk we exist
dispatch(BitCommand, sys.argv, sys.stdin, sys.stdout, __name__)