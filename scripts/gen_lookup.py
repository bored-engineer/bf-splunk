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

# Send the header and the first IP
s.send("begin\nverbose\n" + sys.stdin.readline().strip() + "\n")

# Make s into a file for ease of use
f = s.makefile()

# Read in the header and ignore it
f.readline()

# Use a DictReader to process the "file"
r = csv.DictReader(f,
	delimiter='|',
	quoting=csv.QUOTE_NONE,
	fieldnames=["AS", "IP", "ASPrefix", "ASCountry", "ASRegistry", "ASAllocDate", "ASName"]
)

# Setup a csv writer to stdout
w = csv.DictWriter(sys.stdout, fieldnames=["ASPrefix", "AS", "ASCountry", "ASRegistry", "ASAllocDate", "ASName"])
w.writeheader()

# For each value from cymru
for result in r:

	# Strip all the values since they come with whitespace
	result = { k:v.strip() for k, v in result.iteritems() }
	print result

	# Save the prefix in tree so we don't look it up twice for other IPs in the range
	tree[result["ASPrefix"]] = True

	# Delete the IP
	del result["IP"]

	# Print the prefix to stdout
	w.writerow(result)

	# Keep reading IPs until we hit another new one
	while True:

		# Read in IP
		ip = sys.stdin.readline().strip()

		# If new IP
		if ip not in tree:

			# Send a request for it
			s.send(ip + "\n")
			print ip

			# Stop looping
			break

	