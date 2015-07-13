#!/usr/bin/env python

# Imports
import sys

# Search commands
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class BitCommand(StreamingCommand):

	# The fields to use in comparison
	field1 = Option(doc="", require=True, validate=validators.Fieldname())
	field2 = Option(doc="", require=True, validate=validators.Fieldname())

	# Stream results as needed
	def stream(self, records):

		# Loop each record
		for record in records:

			# Loop each character in field1
			for i, (c1, c2) in enumerate(zip(record[self.field1], record[self.field2])):

				# If it's different, we found our match
				if c1 != c2:

					# Save the byte the flip occured in
					record["bf_byte"] = i

					# Identify the bit where the flip occured
					record["bf_bit"] = '{:08b}'.format(ord(c1) ^ ord(c2)).index('1')

			# Yeild the record
			yield record        
		
# Tell splunk we exist
dispatch(BitCommand, sys.argv, sys.stdin, sys.stdout, __name__)