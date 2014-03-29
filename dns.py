
import datetime
import packetpeeper

CLASS_IN	= 1
CLASS_CS	= 2
CLASS_CH	= 3
CLASS_HS	= 4

TYPE_A		= 1
TYPE_NS		= 2
TYPE_MD		= 3
TYPE_MF		= 4
TYPE_CNAME	= 5
TYPE_SOA	= 6
TYPE_MB		= 7
TYPE_MG		= 8
TYPE_MR		= 9
TYPE_NULL	= 10
TYPE_WKS	= 11
TYPE_PTR	= 12
TYPE_HINFO	= 13
TYPE_MINFO	= 14
TYPE_MX		= 15
TYPE_TXT	= 16

def canDecodeProtocol(protocol, port):
	return (port == 53)

def validatePacketData(packet):
	return True

def shortName():
	return "DNS"

def longName():
	return "DNS"

def readResourceRecord(packet, offset):
	(domain_name, offset) = readName(packet, offset)
	(r_type, r_class, ttl_secs, rd_len) = packetpeeper.unpack(packet, "%ux>H>H>L>H" % offset)
	offset += 10
	rel_offset = offset

	resultList = [domain_name, "%s/%s" % (classStr(r_class), typeStr(r_type)),
				 ["Name", domain_name],
				 ["Type", "%s (%s)" % (typeStr(r_type), typeStrLong(r_type))],
				 ["Class", classStr(r_class)],
				 ["Time to live", str(datetime.timedelta(seconds=ttl_secs))],
				 ["Data length", str(rd_len)]]

	resultDict = {}
	resultDict["Name"] = domain_name
	resultDict["Type"] = typeStr(r_type)
	resultDict["TypeLong"] = typeStrLong(r_type)
	resultDict["Class"] = classStr(r_class)
	resultDict["Time to live"] = str(datetime.timedelta(seconds=ttl_secs))
	resultDict["Data length"] = str(rd_len)
	resultDict["Info"] = ""

	if(r_class == CLASS_IN): # IN class
		if(r_type == TYPE_A): # A: host address, IN specific, tested
			if(rd_len >= 4):
				addr, = packetpeeper.unpack(packet, "%uxA" % rel_offset)
				resultList.append(["Address", addr])
				resultDict["Info"] = addr
		elif(r_type == TYPE_WKS): # WKS: well known service description, IN specific, XXX NEEDS FINISHING AND TESTING
			#if(rd_len >= 5):
			#	(addr, protocol, bitmap) = packetpeeper.unpack(packet, "%ux4sB%us" % (rel_offset, rd_len - 5))
			#	resultList.append(["Address", socket.inet_ntoa(addr)])
			#	resultList.append(["Protocol", str(protocol)])
			# need test data...
			# protocol = TCP, UDP etc
			# bitmap is ports 0 1 2 3 etc, up to 256 bits? bit 1 = port 0.
			pass
	if(r_type == TYPE_NS): # NS: authoritative name server, tested
		name = readName(packet, rel_offset)[0]
		resultList.append(["Name server", name])
		resultDict["Info"] = name
	elif(r_type == TYPE_MD): # MD: mail destination (obsolete)
		name = readName(packet, rel_offset)[0]
		resultList.append(["Mail delivery agent", name])
		resultDict["Info"] = name
	elif(r_type == TYPE_MF): # MF: mail forwarder (obsolete)
		name = readName(packet, rel_offset)[0]
		resultList.append(["Mail forwarding agent", name])
		resultDict["Info"] = name
	elif(r_type == TYPE_CNAME): # CNAME: canonical name for an alias
		name = readName(packet, rel_offset)[0]
		resultList.append(["Primary owner", name])
		resultDict["Info"] = name
	elif(r_type == TYPE_SOA): # SOA: start of zone authority
		(m_name, rel_offset) = readName(packet, rel_offset)
		(r_name, rel_offset) =  readName(packet, rel_offset)
		resultList.append(["Primary source", m_name])
		resultList.append(["Owner mailbox", r_name])
		(serial, refresh, retry, expire, minimum) = packetpeeper.unpack(packet, "%ux>I>I>I>I>I" % rel_offset)
		resultList.append(["Serial", str(serial)])
		resultList.append(["Refresh interval", str(datetime.timedelta(seconds=refresh))])
		resultList.append(["Retry interval", str(datetime.timedelta(seconds=retry))])
		resultList.append(["Expiration limit", str(datetime.timedelta(seconds=expire))])
		resultList.append(["Minimum TTL", str(datetime.timedelta(seconds=minimum))])
		resultDict["Info"] = m_name + " " + r_name
	elif(r_type == TYPE_MB): # MB: mailbox domain name (experimental)
		name = readName(packet, rel_offset)[0]
		resultList.append(["Mailbox owner", name])
		resultDict["Info"] = name
	elif(r_type == TYPE_MG): # MG: mail group member (experimental)
		name = readName(packet, rel_offset)[0]
		resultList.append(["Mailbox group member", name])
		resultDict["Info"] = name
	elif(r_type == TYPE_MR): # MR: mail rename domain name (experimental)
		name = readName(packet, rel_offset)[0]
		resultList.append(["Mailbox rename", name])
		resultDict["Info"] = name
	elif(r_type == TYPE_NULL): # NULL: null RR (experimental)
		pass # no structure to decode
	elif(r_type == TYPE_PTR): # PTR: domain name pointer
		name = readName(packet, rel_offset)[0]
		resultList.append(["Pointer", name])
		resultDict["Info"] = name
	elif(r_type == TYPE_HINFO): # HINFO: host information
		cpu_len, = packetpeeper.unpack(packet, "%uxB" % rel_offset)
		rel_offset += 1
		cpu, = packetpeeper.unpack(packet, "%ux%us" % (rel_offset, cpu_len))
		rel_offset += cpu_len
		os_len,  = packetpeeper.unpack(packet, "%uxB" % rel_offset)
		rel_offset += 1
		os, = packetpeeper.unpack(packet, "%ux%us" % (rel_offset, os_len))
		resultList.append(["CPU", cpu])
		resultList.append(["Operating system", os])
		resultDict["Info"] = cpu + " " + os
	elif(r_type == TYPE_MINFO): # MINFO: mailbox or mail list information
		(r_mailbox, rel_offset) = readName(packet, rel_offset)
		(e_mailbox, rel_offset) =  readName(packet, rel_offset)
		resultList.append(["Mailing list mailbox", r_mailbox])
		resultList.append(["Error mailbox", e_mailbox])
		resultDict["Info"] = r_mailbox + " " + e_mailbox
	elif(r_type == TYPE_MX): # MX: mail exchange
		preference, = packetpeeper.unpack(packet, "%ux>H" % rel_offset)
		(exchange, rel_offset) = readName(packet, rel_offset + 2)
		resultList.append(["Preference", str(preference)])
		resultList.append(["Mail exchange", exchange])
		resultDict["Info"] = str(preference) + " " + exchange
	elif(r_type == TYPE_TXT): # TXT: text strings
		text_len, = packetpeeper.unpack(packet, "%uxB" % rel_offset)
		rel_offset += 1
		text, = packetpeeper.unpack(packet, "%ux%us" % (rel_offset, text_len))
		resultList.append(["Text", text])
		resultDict["Info"] = text
	return ((resultList, resultDict), offset + rd_len)

def decodeResourceRecords(packet, count, offset):
	n_answers, = packetpeeper.unpack(packet, "6x>H")

	records = []
	i = 0
	while(i < count):
		(answer, offset) = readResourceRecord(packet, offset)
		records.append(answer)
		i += 1
	return (records, offset)

def readQuestion(packet, offset):
	(query_name, offset) = readName(packet, offset) # throws RuntimeError
	(query_type, query_class) = packetpeeper.unpack(packet, "%ux>H>H" % (offset))

	resultList = [query_name, "%s/%s" % (queryClassStr(query_class), queryTypeStr(query_type)),
				 ["Name", query_name],
				 ["Type", "%s (%s)" % (queryTypeStr(query_type), queryTypeStrLong(query_type))],
				 ["Class", queryClassStr(query_class)]]

	resultDict = {}
	resultDict["Name"] = query_name
	resultDict["Type"] = queryTypeStr(query_type)
	resultDict["TypeLong"] = queryTypeStrLong(query_type)
	resultDict["Class"] = queryClassStr(query_class)
	return ((resultList, resultDict), offset + 4)

def decodeQuestions(packet, count, offset):
	questions = []
	i = 0
	while(i < count):
		(question, offset) = readQuestion(packet, offset)
		questions.append(question)
		i += 1
	return (questions, offset)

def info(packet):
	(ident, flags, n_questions, n_answers) = packetpeeper.unpack(packet, ">H>H>H>H")

	detailStr = ""

	try:
		(questions, offset) = decodeQuestions(packet, n_questions, 12)
		(answers, offset) = decodeResourceRecords(packet, n_answers, offset)
	except RuntimeError, errorString:
		answers = []
		questions = []
		detailStr = " [malformed packet: %s]" % errorString
	except Exception, e:
		answers = []
		questions = []
		detailStr = " [parse error: %s] " % str(e)

	if(isResponse(flags)):
		for answer in answers:
			detailStr += " " + answer[1]["Type"]
			detailStr += " " + answer[1]["Info"]

		if((flags & 0xF) != 0):
			detailStr += ", " + responseCodeLongStr(flags & 0xF)

		return ("%s response%s" % (opcodeStr((flags & 0x7800) >> 11), detailStr))

	for question in questions:
		detailStr += " " + question[1]["Type"]
		detailStr += " " + question[1]["Name"]

	return ("%s%s" % (opcodeStr((flags & 0x7800) >> 11), detailStr))

def isResponse(flags):
	return bool((flags & 0x8000) >> 15)

def strQRType(flags):
	if(isResponse(flags)):
		return "Response"
	return "Query"

def boolStr(value):
	if(value):
		return "Yes"
	else:
		return "No"

def typeStrLong(value):
	try:
		return ["Host address",
				"Authoritative name server",
				"Mail destination",
				"Mail forwarder",
				"Canonical name",
				"Start of zone authority",
				"Mailbox domain name",
				"Mail group member",
				"Mail rename domain name",
				"Null RR",
				"Well known service description",
				"Domain name pointer",
				"Host information",
				"Mailbox or mail list information",
				"Mail exchange",
				"Text strings"][value - 1]
	except:
		return ("[Unknown type %u]" % value)

def typeStr(value):
	try:
		return ["A", "NS", "MD", "MF",
				"CNAME", "SOA", "MB", "MG",
				"MR", "NULL", "WKS", "PTR",
				"HINFO", "MINFO", "MX", "TXT"][value - 1]
	except:
		return ("[Unknown type %u]" % value)

def queryTypeStrLong(value):
	try:
		return ["Zone transfer",
				"Mailbox records",
				"Mail agent RRs",
				"All records"][value - 252]
	except:
		return typeStrLong(value)

def queryTypeStr(value):
	try:
		return ["AXFR", "MAILB", "MAILA", "ANY"][value - 252]
	except:
		return typeStr(value)

def classStr(value):
	try:
		return ["Internet",
				"CSNET",
				"Chaos",
				"Hesiod"][value - 1]
	except:
		return ("[Unknown class %u]" % value)

def queryClassStr(value):
	if(value == 255):
		return "*"
	return classStr(value)

def opcodeStr(value):
	try:
		return ["Standard query", "Inverse query", "Server status request"][value]
	except:
		return "Unknown"

def responseCodeLongStr(value):
	try:
		return ["No error condition",
				"Name server unable to interpret query",
				"Server failure",
				"No such name",
				"Name server does not support requested kind of query",
				"Name server refuses to perform requested operation"][value]
	except:
		return "Unknown"

def readName(packet, offset):
	(labels, offset) = readLabelsRecurse(packet, offset, [])
	if(len(labels) < 1):
		return ("Root", offset)
	return (".".join(labels), offset)

def readLabelsRecurse(packet, offset, prevOffsets):
	labels = []

	if(offset in prevOffsets):
		raise RuntimeError("Recursive label at offset %u" % offset)

	prevOffsets.append(offset)

	while True:
		label_len, = packetpeeper.unpack(packet, "%uxB" % offset)
		label_len = int(label_len)

		if((label_len & 0xC0) == 0xC0): # pointer
			ptr, = packetpeeper.unpack(packet, "%ux>H" % offset)
			ptr = ptr & 0x3FFF
			if(ptr == offset):
				raise RuntimeError("Self-referencing label at offset %u" % offset)
			labels += readLabelsRecurse(packet, ptr, prevOffsets)[0]
			offset += 2
			break
		elif((label_len & 0x3F) == 0): # end of label
			offset += 1
			break
		else: # label text
			offset += 1
			label, = packetpeeper.unpack(packet, "%ux%us" % (offset, (label_len & 0x3F)))
			offset = offset + (label_len & 0x3F)
		labels.append(label)

	return (labels, offset)

def descriptionTree(packet):
	(ident, flags, n_questions, n_answers, n_authority, n_additional) = packetpeeper.unpack(packet, ">H>H>H>H>H>H")

	ret =	["DNS",
				["Identification", "0x%.4x" % ident],
				["Flags", "0x%.4x" % flags,
					["QR", strQRType(flags)], 
					["Opcode", opcodeStr((flags & 0x7800) >> 11)],
					["Authoritative Answer", boolStr((flags & 0x400) >> 10)],
					["Truncated", boolStr((flags & 0x200) >> 9)],
					["Recursion Desired", boolStr((flags & 0x100) >> 8)],
					["Recursion Available", boolStr((flags & 0x80) >> 7)],
					["(zero)", "0x%x" % ((flags & 0x70) >> 4)],
					["Response code", responseCodeLongStr(flags & 0xF)]]]

	try:
		temp = ["Questions", "%hu" % n_questions]
		(questions, offset) = decodeQuestions(packet, n_questions, 12)
		for question in questions:
			temp.append(question[0])
		ret.append(temp)

		temp = ["Answer RRs", "%hu" % n_answers]
		(records, offset) = decodeResourceRecords(packet, n_answers, offset)
		for record in records:
			temp.append(record[0])
		ret.append(temp)

		temp = ["Authority RRs", "%hu" % n_authority]
		(records, offset) = decodeResourceRecords(packet, n_authority, offset)
		for record in records:
			temp.append(record[0])
		ret.append(temp)

		temp = ["Additional Information RRs", "%hu" % n_additional]
		(records, offset) = decodeResourceRecords(packet, n_additional, offset)
		for record in records:
			temp.append(record[0])
		ret.append(temp)

	except RuntimeError, errorString:
		ret.append(["Error", str(errorString)])
	except Exception, e:
		ret.append(["Error", str(e)])

	return ret

def columnIdentifiers():
	return [["Identification", "DNS Ident"],
			["Flags", "DNS Flags"],
			["Number of questions", "DNS # Questions"],
			["Number of answer RRs", "DNS # Answers"],
			["Number of authority RRs", "DNS # Authority"],
			["Number of additional RRs", "DNS # Additional"]]

def columnStringForIndex(packet, index):
	if(index == 0): # identification
		return "0x%.4x" % packetpeeper.unpack(packet, ">H")[0]
	if(index == 1): # flags
		return "0x%.4x" % packetpeeper.unpack(packet, "2x>H")[0]
	if(index == 2): # n questions
		return "%u" % packetpeeper.unpack(packet, "4x>H")[0]
	if(index == 3): # n answers
		return "%u" % packetpeeper.unpack(packet, "6x>H")[0]
	if(index == 4): # n authority
		return "%u" % packetpeeper.unpack(packet, "8x>H")[0]
	if(index == 5): # n additional
		return "%u" % packetpeeper.unpack(packet, "10x>H")[0]
	return None

def compareColumnForIndex(packet_a, packet_b, index):
	if(index == 0): # identification
		val_a, = packetpeeper.unpack(packet_a, ">H")
		val_b, = packetpeeper.unpack(packet_b, ">H")
	elif(index == 1): # flags
		val_a, = packetpeeper.unpack(packet_a, "2x>H")
		val_b, = packetpeeper.unpack(packet_b, "2x>H")
	elif(index == 2): # n questions
		val_a, = packetpeeper.unpack(packet_a, "4x>H")
		val_b, = packetpeeper.unpack(packet_b, "4x>H")
	elif(index == 3): # n answers
		val_a, = packetpeeper.unpack(packet_a, "6x>H")
		val_b, = packetpeeper.unpack(packet_b, "6x>H")
	elif(index == 4): # n authority
		val_a, = packetpeeper.unpack(packet_a, "8x>H")
		val_b, = packetpeeper.unpack(packet_b, "8x>H")
	elif(index == 5): # n additional
		val_a, = packetpeeper.unpack(packet_a, "10x>H")
		val_b, = packetpeeper.unpack(packet_b, "10x>H")
	else:
		return 0

	if(val_a > val_b):
		return 1
	if(val_a < val_b):
		return -1

	return 0

def isValidData(packet):
	return packetpeeper.size(packet) > 12
