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

# http://standards.ieee.org/regauth/oui/oui.txt

import struct

datfile = open('ethernet-manufacturers.oui', 'w')
infile = open('oui.txt', 'r')
maxlen = 0
slist = []
oui2manufacturer = {}

for line in infile.readlines():

	words = line.split("(hex)")

	if len(words) == 2:
		hbytes = words[0].split("-")
		oui = (long(hbytes[0], 16) << 16) + (long(hbytes[1], 16) << 8) + long(hbytes[2], 16)

		if(len(words[1].strip()) > maxlen):
			maxlen = len(words[1].strip())

		if(not oui2manufacturer.has_key(oui)):
			slist.append([oui, words[1].strip()])

		oui2manufacturer[oui] = words[1].strip()

# 2 bytes magic, 2 bytes record size, 2 bytes number of records
# records are 2 bytes of string length, then <string length> of text, followed
# by dead space up until <record size>

print "Max = %d" % maxlen
print "slist len = %u" % len(slist)
print "dict len = %u" % len(oui2manufacturer)

bytes = struct.pack("H", 0x1C0D) # magic
datfile.write(bytes)

bytes = struct.pack(">HH", maxlen + 2 + 4, len(slist)) # record size, number of records
datfile.write(bytes)

slist.sort()

for oui in slist:
	bytes = struct.pack(">LH" + ('%u' % maxlen) + "s", oui[0], len(oui[1]), oui[1])
	datfile.write(bytes);
