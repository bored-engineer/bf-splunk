#!/usr/bin/env python

# Imports
import sys
import csv
import socket
import SubnetTree

# Create a tree
tree = SubnetTree.SubnetTree()

# Create a new socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to Team Cymru (https://www.team-cymru.org/IP-ASN-mapping.html)
s.connect(("whois.cymru.com", 43))

# Send the header
s.send("begin\nverbose\n")

# Make s into a file for ease of use
f = s.makefile()

# Read in the header and ignore it
f.readline()

# Use a DictReader to process the "file"
r = csv.DictReader(f,
	delimiter='|',
	quoting=csv.QUOTE_NONE,
	skipinitialspace=True,
	fieldnames=["AS", "Ignore", "ASPrefix", "ASCountry", "ASRegistry", "ASAllocDate", "ASName"]
)

# Setup a csv writer to stdout
w = csv.DictWriter(sys.stdout, fieldnames=["ASPrefix", "AS", "ASCountry", "ASRegistry", "ASAllocDate", "ASName"])
w.writeheader()

# For each IP
for line in sys.stdin:

	# Check if not already looked up in tree
	if line.strip() not in tree:

		# Look it up
		s.send(line.strip() + "\n")

		# Get the response from the socket
		result = next(r)

		# Delete
		del result["Ignore"]

		# Strip all the values since they come with whitespace
		result = { k:v.strip() for k, v in result.iteritems() }

		# Catch and ignore bad prefixs
		try: 		

			# Save the prefix in tree so we don't look it up twice for other IPs in the range
			tree[result["ASPrefix"]] = True

			# Print the prefix to stdout
			w.writerow(result)

		# Ignore the error
		except:
			pass