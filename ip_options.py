
#
# This garbage is a work in progress :-)
#

import packetpeeper
import socket

IPOPT_EOL = 0			# end of option list, no length
IPOPT_NOP = 1			# no operation, no length
IPOPT_RR = 7			# record packet route, variable length
IPOPT_TS = 68			# internet timestamp, variable length
IPOPT_SECURITY = 130	# provide s,c,h,tcc, length 11
IPOPT_LSRR = 131		# loose source route, variable length
IPOPT_SATID = 136		# satnet id, length 4
IPOPT_SSRR = 137		# strict source route, variable length
IPOPT_RA = 148			# router alert, length ?

def canDecodeProtocol(protocol, port):
	return False

def isValidData(packet):
	return False

def validatePacketData(packet):
	return True

def shortName():
	return "IPv4 Options"

def longName():
	return "IPv4 Options"

def info(packet):
	return "Blah"

def descriptionTree(packet):
	len = packetpeeper.size(packet)
	items = []
	offset = 0

	try:
		while(offset < len):
			option_type, = packetpeeper.unpack(packet, "%uxB" % offset)
			if(option_type == IPOPT_EOL):
				items.append(["End of options"])
				offset += 1
				break
			elif(option_type == IPOPT_NOP):
				items.append(["No operation"])
				offset += 1
			else:
				opt_len, = packetpeeper.unpack(packet, "%uxB" % (offset + 1))

				if(option_type == IPOPT_RR):
					pointer, = packetpeeper.unpack(packet, "%uxB" % (offset + 2))
					items.append(["Record route", ["Pointer", "%u" % pointer]])
				elif(option_type == IPOPT_TS):
					pointer, = packetpeeper.unpack(packet, "%uxB" % (offset + 2))
					oflow_flag, = packetpeeper.unpack(packet, "%uxB" % (offset + 3))

					overflow = (oflow_flag & 0xF0) >> 4;
					flag = oflow_flag & 0x0F;

					if(flag == 1 or flag == 3):
						#print "dual"
						size = 8
					else:
						size = 4

					addrs = []

					# should cap this to the length
					if(pointer >= (5 + size)):
						n = (pointer - 5) / size

						while(i < n):
							if(size == 8):
								(addr,tstamp) = packetpeeper.unpack(packet, "%ux4s>I" % (offset + 4 + (i * size)))
							else:
								tstamp, = packetpeeper.unpack(packet, ">I" % (offset + 4 + (i * size)))

							addrs.append(["Address", socket.inet_ntoa(addr)])
							i += 1

					items.append(["Internet timestamp", ["Pointer", "%u" % pointer],
														["Overflow", "%u" % overflow],
														["Flag", "%u" % flag]] + addrs)
				elif(option_type == IPOPT_SECURITY):
					items.append(["Security"])
				elif(option_type == IPOPT_LSRR or option_type == IPOPT_SSRR):
					pointer, = packetpeeper.unpack(packet, "%uxB" % (offset + 2))
					if(pointer >= 4 and opt_len >= 7):
						addrs = unpackAddrs(packet, opt_len - 3, offset + 3)
					else:
						addrs = []

					if(pointer >= 4 and opt_len >= 7 and pointer <= (opt_len - 3)):
						addr, = packetpeeper.unpack(packet, "%ux4s" % (pointer - 1))
						ptrStr = "%u (%s)" % (pointer, socket.inet_ntoa(addr))
					else:
						ptrStr = "%u" % pointer

					if(option_type == IPOPT_LSRR):
						typeStr = "Loose source routing"
					else:
						typeStr = "Strict source routing"

					items.append([typeStr, ["Pointer", ptrStr]] + addrs)
				elif(option_type == IPOPT_SATID):
					if(opt_len == 4):
						stream_id, = packetpeeper.unpack(packet,  "%ux>H" % (offset + 2))
						items.append(["Stream ID", "%u" % stream_id])
				elif(option_type == IPOPT_RA):
					items.append(["Router alert"])
				else:
					items.append(["Unknown option type", "0x%X" % option_type])
					break

				offset += opt_len
	except Exception, e:
		print "exception" + str(e)
		pass

	ret = ["Options"] + items

	print ret

	return ret

def unpackAddrs(packet, len, offset):
	ret = []
	n = len / 4
	i = 0

	while(i < n):
		addr, = packetpeeper.unpack(packet, "%ux4s" % (offset + (i * 4)))
		ret.append(["Address", socket.inet_ntoa(addr)])
		i += 1

	return ret

def columnIdentifiers():
	return ["blah"]

def columnStringForIndex(packet, index):
	return "Blah"

def compareColumnForIndex(packet_a, packet_b, index):
	return 0
