#!/usr/bin/python

# Packet Peeper
# Copyright 2006, 2007, 2008, 2014 Chris E. Holloway
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import struct

datfile_tcp = "port-numbers-tcp.port"
datfile_udp = "port-numbers-udp.port"
porturl = "http://www.iana.org/assignments/port-numbers"
portfile = "port-numbers"

#print "Pre-processing %s into %s" % (portfile, datfile)

infile = open(portfile, 'r')
datfile_tcp = open(datfile_tcp, 'w')
datfile_udp = open(datfile_udp, 'w')

maxname = 0
maxdesc = 0
port2name = {}

for line in infile.readlines():

	# remove comments
	line = line.split("#", 1)

	if(line == [] or line[0] == ""):
		continue

	# split on whitespace
	tok = line[0].split(None, 2)

	if(len(tok) != 3):
		continue

	tok2 = tok[1].split("/")

	if(len(tok2) != 2):
		continue

	proto = tok2[1]

	if(proto != "tcp" and proto != "udp"):
		continue

	name = tok[0]
	description = tok[2].strip()

	tok3 = tok2[0].split("-")

	if(len(tok3) == 2):
		lport = int(tok3[0])
		hport = int(tok3[1])
	else:
		lport = hport = int(tok2[0])

	port = lport

	if(len(name) > maxname):
		maxname = len(name)

	if(len(description) > maxdesc):
		maxdesc = len(description)

	if(port2name.has_key(port)):
		port2name[port].append([name, description, proto])
	else:
		port2name[port] = [[name, description, proto]]


# file format;
# 2 byte magic number.
# record size
# number of records
# [ ... records ...]
# records are 2 bytes of string length, 1 byte flags, then <string length> of text, followed by
# dead space up until <record size>. 
#

# tcp dat

bytes = struct.pack("H", 0x1A0D) # magic
datfile_tcp.write(bytes)

bytes = struct.pack(">H", maxdesc + 3)
datfile_tcp.write(bytes)

port = 1

while (port < pow(2,16)):
	try:
		tcpservices = []

		# filter out non-tcp services
		for service in port2name[port]:
			if(service[2] == "tcp"):
				tcpservices.append(service)

		# Skip over duplicate entries
		i = 0
		badService = False
		while(i < (len(tcpservices) - 1)):
			if(tcpservices[i][1] != tcpservices[i + 1][1]):
				print ("Service mismatch on port %u between:\n\t" % port) + tcpservices[i][1] + "\n\tand:\n\t" + tcpservices[i + 1][1] + "\n"
				badService = True
			i = i + 1

		if(badService or len(tcpservices) < 1):
			raise KeyError

		# Check for an equivalent UDP service
		i = 0
		hasEquivalent = False
		while(i < (len(port2name[port]) - 1)):
			servicea = port2name[port][i]
			serviceb = port2name[port][i + 1]
			if((servicea[2] == "tcp" and serviceb[2] == "udp") or (servicea[2] == "udp" and serviceb[2] == "tcp")):
				hasEquivalent = True
			i = i + 1

		# guaranteed to succeed, as we already raised KeyError on len(tcpservices) < 1
		for service in port2name[port]:
			if(service[2] == "tcp"):
				description = service[1]
				break

		if(hasEquivalent):
			flags = 0x1
		else:
			flags = 0x0
		bytes = struct.pack(">HB" + ('%u' % maxdesc) + "s", len(description), flags, description)
		datfile_tcp.write(bytes)

	except KeyError:
			bytes = struct.pack(">HB" + ('%u' % maxdesc) + "s", 0, 0, "")
			datfile_tcp.write(bytes)

	port = port + 1

# udp dat

bytes = struct.pack("H", 0x1B0D) # magic
datfile_udp.write(bytes)

bytes = struct.pack(">H", maxdesc + 3)
datfile_udp.write(bytes)

port = 1
while (port < pow(2,16)):
	try:
		udpservices = []

		# filter out non-udp services
		for service in port2name[port]:
			if(service[2] == "udp"):
				udpservices.append(service)

		# Skip over duplicate entries
		i = 0
		badService = False
		while(i < (len(udpservices) - 1)):
			if(udpservices[i][1] != udpservices[i + 1][1]):
				print ("Service mismatch on port %u between:\n\t" % port) + udpservices[i][1] + "\n\tand:\n\t" + udpservices[i + 1][1] + "\n"
				badService = True
			i = i + 1

		if(badService or len(udpservices) < 1):
			raise KeyError

		# Check for an equivalent TCP service
		i = 0
		hasEquivalent = False
		while(i < (len(port2name[port]) - 1)):
			servicea = port2name[port][i]
			serviceb = port2name[port][i + 1]
			if((servicea[2] == "udp" and serviceb[2] == "tcp") or (servicea[2] == "tcp" and serviceb[2] == "udp")):
				hasEquivalent = True
			i = i + 1

		# guaranteed to succeed, as we already raised KeyError on len(udpservices) < 1
		for service in port2name[port]:
			if(service[2] == "udp"):
				description = service[1]
				break

		if(hasEquivalent):
			flags = 0x1
		else:
			flags = 0x0
		bytes = struct.pack(">HB" + ('%u' % maxdesc) + "s", len(description), flags, description)
		datfile_udp.write(bytes)

	except KeyError:
			bytes = struct.pack(">HB" + ('%u' % maxdesc) + "s", 0, 0, "")
			datfile_udp.write(bytes)

	port = port + 1
