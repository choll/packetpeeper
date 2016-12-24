/*
 * Packet Peeper
 * Copyright 2006, 2007, 2008, 2014 Chris E. Holloway
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSArchiver.h>
#include "Packet.h"
#include "IPV4Decode.h"
#include "TCPDecode.h"
#include "UDPDecode.h"
#include "ICMPDecode.h"
#include "HostCache.hh"
#include "in_cksum.h"
#include "strfuncs.h"

static NSString *names[][2] =	{{@"Type", @"ICMP Type"},
								{@"Code", @"ICMP Code"},
								{@"Checksum", @"ICMP Cksum"},
								{@"Identifier", @"ICMP Id"},
								{@"Sequence Number", @"ICMP Seq No."},
								{@"Gateway IP", @"ICMP GW IP"},
								{@"Parameter Pointer", @"ICMP PPtr"},
								{@"Subnet Mask", @"ICMP SNet. Mask"},
								{@"Originate Timestamp", @"ICMP OTstamp"},
								{@"Receive Timestamp", @"ICMP RTstamp"},
								{@"Transmit Timestamp", @"ICMP TTstamp"},
								{@"Gateway Hostname", @"ICMP GW Host"},
								{@"Message Type", @"ICMP Msg Type"},
								{@"Description", @"ICMP Desc"},
								{@"Parameter Pointer Value", @"ICMP PPtr Val"},
								{@"Paramater Pointer Field", @"ICMP PPtr Field"},
								{@"Originate Timestamp Meaning", @"ICMP OTstamp *"},
								{@"Receive Timestamp Meaning", @"ICMP RTstamp *"},
								{@"Transmit Timestamp Meaning", @"ICMP TTstamp *"}
								/* router query and response */ };

@implementation ICMPDecode

- (id)initWithData:(NSData *)dataVal parent:(id <PPDecoderParent>)parentVal
{
	struct icmp *hdr;

	if(dataVal == nil)
		return nil;

	if((self = [super init]) != nil) {
		parent = parentVal;
		fields = 0;

		/* not enough data is represented by returning nil */
		if([dataVal length] < ICMPDECODE_HDR_MIN)
			goto err;

		hdr = (struct icmp *)[dataVal bytes];

		type = hdr->icmp_type;
		code = hdr->icmp_code;
		sum = hdr->icmp_cksum;
		calced_sum = 0;

		frontSize = 8;

		switch(type) {
			/* echo reply or request, no length check reqd */
			case ICMP_ECHOREPLY:
			case ICMP_ECHO:
			/* information request or reply (obsolete) */
			case ICMP_IREQ:
			case ICMP_IREQREPLY:
				cont.upper.idseq.ident = hdr->icmp_id;
				cont.upper.idseq.seq = hdr->icmp_seq;
				fields = ICMPDECODE_IDSEQ;
				break;

			case ICMP_SOURCEQUENCH: /* source quench */
				cont.upper.idseq.ident = hdr->icmp_id;
				cont.upper.idseq.seq = hdr->icmp_seq;
				fields = ICMPDECODE_IDSEQ;
				[self decodeIPData:dataVal];
				break;

			case ICMP_TIMXCEED: /* time exceeded */
				cont.upper.idseq.ident = hdr->icmp_id;
				cont.upper.idseq.seq = hdr->icmp_seq;
				fields = ICMPDECODE_IDSEQ;
				[self decodeIPData:dataVal];
				break;

			case ICMP_UNREACH: /* destination unreachable -- additions in RFC1191? */
				cont.upper.idseq.ident = hdr->icmp_id;
				cont.upper.idseq.seq = hdr->icmp_seq;
				fields = ICMPDECODE_IDSEQ;
				[self decodeIPData:dataVal];
				break;

			case ICMP_REDIRECT: /* redirect */
				cont.upper.gateway = hdr->icmp_gwaddr;
				fields = ICMPDECODE_GWADDR;
				[self decodeIPData:dataVal];
				break;

			case ICMP_ROUTERADVERT: /* router advertisement -- RFC1256, &pg124 */
			// code = 0
			// no id seq, instead;
			//	1 byte num addrs		= number of router addresses in the msg.
			//	1 byte addr entry size	= number of 32bit words of info per router addr (2 here)
			//	2 bytes lifetime		= max seconds the address may be considered valid
			// addr = in_addr, pref = 32bit number
			// then router address + pref level, router address + pref, ... etc
				break;

			case ICMP_ROUTERSOLICIT: /* router solicitation */
			// code 0
			// no id seq, just `reserved', i.e padding because min length 8.
				break;

			case ICMP_PARAMPROB: /* parameter problem */
				cont.upper.pptr = hdr->icmp_pptr;
				fields = ICMPDECODE_PARAMPTR;
				[self decodeIPData:dataVal];
				break;

			case ICMP_TSTAMP: /* timestamp reply or request */
			case ICMP_TSTAMPREPLY:
				cont.upper.idseq.ident = hdr->icmp_id;
				cont.upper.idseq.seq = hdr->icmp_seq;
				if([dataVal length] < (ICMP_MINLEN + sizeof(cont.lower.tstamp))) {
					fields = ICMPDECODE_IDSEQ;
					break;
				}
				cont.lower.tstamp.orig = hdr->icmp_otime;
				cont.lower.tstamp.recv = hdr->icmp_rtime;
				cont.lower.tstamp.trans = hdr->icmp_ttime;
				fields = (ICMPDECODE_IDSEQ | ICMPDECODE_TSTAMP);
				break;

			case ICMP_MASKREQ:
			case ICMP_MASKREPLY:
				cont.upper.idseq.ident = hdr->icmp_id;
				cont.upper.idseq.seq = hdr->icmp_seq;
				if([dataVal length] < (ICMP_MINLEN + sizeof(cont.lower.mask))) {
					fields = ICMPDECODE_IDSEQ;
					break;
				}
				cont.lower.mask = hdr->icmp_mask;
				fields = (ICMPDECODE_IDSEQ | ICMPDECODE_SUBMASK);
				break;
		}
	}
	return self;

	err:
		[self dealloc];
		return nil;
}

- (void)setParent:(id <PPDecoderParent>)parentVal
{
	parent = parentVal;
}

- (size_t)frontSize
{
	return frontSize;
}

- (size_t)rearSize
{
	return 0;
}

- (Class)nextLayer
{
	return Nil;
}

+ (NSString *)shortName
{
	return @"ICMP";
}

+ (NSString *)longName
{
	return @"ICMP";
}

- (NSString *)info
{
	return [NSString stringWithFormat:@"%@ (%@)", [self codeString], [self infoType]];
}

- (NSString *)infoType
{
	if(ICMP_INFOTYPE(type))
		return @"Query";
	else
		return @"Error";
}

- (NSString *)codeString
{
	switch(type) {
		case ICMP_ECHOREPLY:							/* echo reply */
			if(code == 0)
				return @"Echo reply";
			else
				break;

		case ICMP_UNREACH:								/* dest unreachable, codes: */
			switch(code) {
				case ICMP_UNREACH_NET:					/* bad net */
					return @"Destination unreachable: Network unreachable";
				case ICMP_UNREACH_HOST:					/* bad host */
					return @"Destination unreachable: Host unreachable";
				case ICMP_UNREACH_PROTOCOL:				/* bad protocol */
					return @"Destination unreachable: Protocol unreachable";
				case ICMP_UNREACH_PORT:					/* bad port */
					return @"Destination unreachable: Port unreachable";
				case ICMP_UNREACH_NEEDFRAG:				/* IP_DF caused drop */
					return @"Destination unreachable: Fragmentation needed but don't-fragment bit set";
				case ICMP_UNREACH_SRCFAIL:				/* src route failed */
					return @"Destination unreachable: Source route failed";
				case ICMP_UNREACH_NET_UNKNOWN:			/* unknown net */
					return @"Destination unreachable: Destination network unknown";
				case ICMP_UNREACH_HOST_UNKNOWN:			/* unknown host */
					return @"Destination unreachable: Destination host unknown";
				case ICMP_UNREACH_ISOLATED:				/* src host isolated, obsolete */
					return @"Destination unreachable: Source host isolated";
				case ICMP_UNREACH_NET_PROHIB:			/* prohibited access */
					return @"Destination unreachable: Destination network administratively prohibited";
				case ICMP_UNREACH_HOST_PROHIB:			/* prohibited access */
					return @"Destination unreachable: Destination host administratively prohibited";
				case ICMP_UNREACH_TOSNET:				/* bad tos for net */
					return @"Destination unreachable: Network unreachable for TOS";
				case ICMP_UNREACH_TOSHOST:				/* bad tos for host */
					return @"Destination unreachable: Host unreachable for TOS";
				case ICMP_UNREACH_FILTER_PROHIB:		/* admin prohib */
					return @"Destination unreachable: Communication administratively prohibited by filtering";
				case ICMP_UNREACH_HOST_PRECEDENCE:		/* host prec vio. */
					return @"Destination unreachable: Host precedence violation";
				case ICMP_UNREACH_PRECEDENCE_CUTOFF:	/* prec cutoff */
					return @"Destination unreachable: Precedence cutoff in effect";
			}
			break;

		case ICMP_SOURCEQUENCH:		/* packet lost, slow down */
			if(code == 0)
				return @"Source quench";
			else
				break;

		case ICMP_REDIRECT:					/* shorter route, codes: */
			switch(code) {
				case ICMP_REDIRECT_NET:		/* for network */
					return @"Redirect: Redirect for network";
				case ICMP_REDIRECT_HOST:	/* for host */
					return @"Redirect: Redirect for host";
				case ICMP_REDIRECT_TOSNET:  /* for tos and net */
					return @"Redirect: Redirect for type-of-service and network";
				case ICMP_REDIRECT_TOSHOST: /* for tos and host */
					return @"Redirect: Redirect for type-of-service and host";
			}
			break;

		case ICMP_ECHO:		/* echo service */
			if(code == 0)
				return @"Echo request";
			else
				break;

		case ICMP_ROUTERADVERT:		/* router advertisement */
			if(code == 0)
				return @"Router advertisement";
			else
				break;

		case ICMP_ROUTERSOLICIT:	/* router solicitation */
			if(code == 0)
				return @"Router solicitation";
			else
				break;
	
		case ICMP_TIMXCEED:						/* time exceeded, code: */
			switch(code) {
				case ICMP_TIMXCEED_INTRANS:		/* ttl==0 in transit */
					return @"Time exceeded: Time-to-live equals 0 during transit";
				case ICMP_TIMXCEED_REASS:		/* ttl==0 in reass */
					return @"Time exceeded: Time-to-live equals 0 during reassembly";
			}
			break;
	
		case ICMP_PARAMPROB:		/* ip header bad */
			switch(code) {
				case ICMP_PARAMPROB_ERRATPTR:   /* error at param ptr */
					return @"Parameter problem: IP header bad";
				case ICMP_PARAMPROB_OPTABSENT:  /* req. opt. absent */
					return @"Parameter problem: Required option missing";
				case ICMP_PARAMPROB_LENGTH:		/* bad length, xxx not in stevens tcpip */
					return @"Parameter problem: Invalid length";
			}
			break;

		case ICMP_TSTAMP:		/* timestamp request */
			if(code == 0)
				return @"Timestamp request";
			else
				break;

		case ICMP_TSTAMPREPLY:  /* timestamp reply */
			if(code == 0)
				return @"Timestamp reply";
			else
				break;

		case ICMP_IREQ:			/* information request */
			if(code == 0)
				return @"Information request";
			else
				break;

		case ICMP_IREQREPLY:	/* information reply */
			if(code == 0)
				return @"Information reply";
			else
				break;

		case ICMP_MASKREQ:		/* address mask request */
			if(code == 0)
				return @"Address mask request";
			else
				break;

		case ICMP_MASKREPLY:	/* address mask reply */
			if(code == 0)
				return @"Address mask reply";
			else
				break;	
	}

	return @"Unknown type/code combination";
}

- (NSString *)gateway
{
	if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_GWADDR)
		return ipaddrstr(&cont.upper.gateway, sizeof(cont.upper.gateway));
	return nil;
}

- (NSString *)resolvGateway
{
	if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_GWADDR)
		return [[parent hostCache] hostWithAddressASync:&cont.upper.gateway returnCode:NULL];

	return nil;
}

- (id <OutlineViewItem>)resolvCallback:(void *)data
{
	OutlineViewItem *ret;
	NSString *resolved;
	int retcode;

	ret = [[OutlineViewItem alloc] init];

	if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_GWADDR) {
		[ret addObject:@"Hostname"];

		if((resolved = [[parent hostCache] hostWithAddressASync:data returnCode:&retcode]) == nil) {
			switch(retcode) {
				case HOSTCACHE_NONAME:
					[ret addObject:@"Lookup failed"];
					break;

				case HOSTCACHE_INPROG:
					[ret addObject:@"Lookup in progress"];
					break;

				default:
					[ret addObject:@"Lookup error"];
					break;
			}
		} else
			[ret addObject:resolved];
	}

	return [ret autorelease];
}

- (stacklev)level
{
	return SL_NETWORK;
}

/* ColumnIdentifier protocol methods */

+ (NSArray *)columnIdentifiers
{
	ColumnIdentifier *colIdent;
	NSMutableArray *ret;
	unsigned int i;

	ret = [[NSMutableArray alloc] initWithCapacity:sizeof(names) / sizeof(names[0])];

	for(i = 0; i < sizeof(names) / sizeof(names[0]) ; ++i) {
		colIdent = [[ColumnIdentifier alloc] initWithDecoder:[self class] index:i longName:names[i][0] shortName:names[i][1]];
		[ret addObject:colIdent];
		[colIdent release];
	}

	return [ret autorelease];
}

- (NSString *)columnStringForIndex:(unsigned int)fieldIndex
{
	switch(fieldIndex) {
		case 0:
			return [NSString stringWithFormat:@"%u", type];
			/* NOTREACHED */

		case 1:
			return [NSString stringWithFormat:@"%u", code];
			/* NOTREACHED */

		case 2:
			return [NSString stringWithFormat:@"0x%.4x", sum];
			/* NOTREACHED */

		case 3:
			if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ)
				return [NSString stringWithFormat:@"%u", cont.upper.idseq.ident];
			break;

		case 4:
			if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ)
				return [NSString stringWithFormat:@"%u", cont.upper.idseq.seq];
			break;

		case 5:
			return [self gateway];
			/* NOTREACHED */

		case 6:
			if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_PARAMPTR)
				return [NSString stringWithFormat:@"%u", cont.upper.pptr];
			break;

		case 7:
			if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_SUBMASK)
				return ipaddrstr(&cont.lower.mask, sizeof(cont.lower.mask)); // [NSString stringWithFormat:@"%u", cont.lower.mask];
			break;

		case 8:
			if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP)
				return [NSString stringWithFormat:@"%u", cont.lower.tstamp.orig];
			break;

		case 9:
			if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP)
				return [NSString stringWithFormat:@"%u", cont.lower.tstamp.recv];
			break;

		case 10:
			if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP)
				return [NSString stringWithFormat:@"%u", cont.lower.tstamp.trans];
			break;

		case 11:
			{
				NSString *ret;
				if((ret = [self resolvGateway]) == nil)
					ret = [self gateway];
				return ret;
			}
			/* NOTREACHED */

		case 12:
			return [self infoType];
			/* NOTREACHED */

		case 13:
			return [self codeString];
			/* NOTREACHED */

		case 14:
			// pptr value
		case 15:
			// pptr field
		case 16:
			// ostamp mean	-- 32bits of milliseconds since midnight UT (Universal Time? -- wrs sez millsec since midnight Coordinated Universal Time)
		case 17:
			// rstamp mean
		case 18:
			// tstamp mean
			break;

	}

	return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
	return NSOrderedSame;
}

/* OutlineViewItem protocol methods */

- (BOOL)expandable
{
	return YES;
}

- (size_t)numberOfChildren
{
	return 3 + (((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ) * 2) +	/* only one of these 3 is present */
			   (((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_GWADDR) * 1) +
			   (((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_PARAMPTR) * 1) +

			   (((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_IP) * 1) +
			   (((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_UDP) * 2) + /* UDP and TCP include IP */
			   (((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TCP) * 2) +
               (((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_SUBMASK) * 1) +
               (((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP) * 3);
}

- (id)childAtIndex:(int)fieldIndex
{
	OutlineViewItem *ret;
	NSString *str;

	ret = nil;

	switch(fieldIndex) {
		case 0:
			ret = [[OutlineViewItem alloc] init];
			[ret addObject:names[0][0]];
			str = [[NSString alloc] initWithFormat:@"%u", type];
			[ret addObject:str];
			[str release];

			/* description */
			[ret addChildWithObjects:names[14][0], [self codeString], nil];

			/* information type*/
			[ret addChildWithObjects:names[13][0], [self infoType], nil];
			break;

		case 1:
			ret = [[OutlineViewItem alloc] init];
			[ret addObject:names[1][0]];
			str = [[NSString alloc] initWithFormat:@"%u", code];
			[ret addObject:str];
			[str release];
			break;

		case 2:
			ret = [[OutlineViewItem alloc] init];
			[ret addObject:names[2][0]];
			if(sum == [self computedChecksum])
				str = [[NSString alloc] initWithFormat:@"0x%.4x (correct)", sum];
			else
				str = [[NSString alloc] initWithFormat:@"0x%.4x (incorrect, should be 0x%.4x)", sum, [self computedChecksum]];
			[ret addObject:str];
			[str release];
			break;

		case 3:
			if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ) {
				ret = [[OutlineViewItem alloc] init];
				[ret addObject:names[3][0]];
				str = [[NSString alloc] initWithFormat:@"%u", cont.upper.idseq.ident];
				[ret addObject:str];
				[str release];
			} else if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_GWADDR) {
				ret = [[OutlineViewItem alloc] init];
				[ret addObject:names[5][0]];
				[ret addObject:[self gateway]];
				[ret addChildWithCallback:self selector:@selector(resolvCallback:) data:&cont.upper.gateway];
			} else if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_PARAMPTR) {
				ret = [[OutlineViewItem alloc] init];
				[ret addObject:names[6][0]];
				str = [[NSString alloc] initWithFormat:@"%u", cont.upper.pptr];
				[ret addObject:str];
				[str release];
			}
			break;

		case 4:
			if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ) {
				ret = [[OutlineViewItem alloc] init];
				[ret addObject:names[4][0]];
				str = [[NSString alloc] initWithFormat:@"%u", cont.upper.idseq.seq];
				[ret addObject:str];
				[str release];
			} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP) {
				ret = [[OutlineViewItem alloc] init];
				[ret addObject:names[8][0]];
				str = [[NSString alloc] initWithFormat:@"%u", cont.lower.tstamp.orig];
				[ret addObject:str];
				[str release];
			} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_SUBMASK) {
				ret = [[OutlineViewItem alloc] init];
				[ret addObject:names[7][0]];
				[ret addObject:ipaddrstr(&cont.lower.mask, sizeof(cont.lower.mask))];
			} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_IP) /* the order of this if statement is significant, as we may have IDSEQ and IP, in which case IPSEQ comes first */
				return cont.lower.ipdata.ipdec;
			break;

		case 5:
			if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ) {
				if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP) {
					ret = [[OutlineViewItem alloc] init];
					[ret addObject:names[8][0]];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.tstamp.orig];
					[ret addObject:str];
					[str release];
				} else //if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_IP) // ICMPDECODE_IP isnt set properly
					return cont.lower.ipdata.ipdec;
			} else {
				if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP) {
					ret = [[OutlineViewItem alloc] init];
					[ret addObject:names[9][0]];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.tstamp.recv];
					[ret addObject:str];
					[str release];
				} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TCP) { /* XXX TODO: Make TCPDecode able to decode 8 bytes */
					OutlineViewItem *child;

					ret = [[OutlineViewItem alloc] init];
					[ret addObject:[[TCPDecode class] longName]];

					/* TCP src port child */
					child = [[OutlineViewItem alloc] init];
					[child addObject:@"Source Port"];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.ipdata.payload.tcphdr.sport];
					[child addObject:str];
					[str release];
					[ret addChild:child];
					[child release];

					/* TCP dst port child */
					child = [[OutlineViewItem alloc] init];
					[child addObject:@"Destination Port"];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.ipdata.payload.tcphdr.dport];
					[child addObject:str];
					[str release];
					[ret addChild:child];
					[child release];

					/* TCP seq. no. child */
					child = [[OutlineViewItem alloc] init];
					[child addObject:@"Sequence Number"];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.ipdata.payload.tcphdr.seq];
					[child addObject:str];
					[str release];
					[ret addChild:child];
					[child release];
				} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_UDP)
					return cont.lower.ipdata.payload.udpdec;
			}
			break;

		case 6:
			if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ) {
				if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP) {
					ret = [[OutlineViewItem alloc] init];
					[ret addObject:names[9][0]];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.tstamp.recv];
					[ret addObject:str];
					[str release];
				} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TCP) {
					OutlineViewItem *child;

					ret = [[OutlineViewItem alloc] init];
					[ret addObject:[[TCPDecode class] longName]];

					/* TCP src port child */
					child = [[OutlineViewItem alloc] init];
					[child addObject:@"Source Port"];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.ipdata.payload.tcphdr.sport];
					[child addObject:str];
					[str release];
					[ret addChild:child];
					[child release];

					/* TCP dst port child */
					child = [[OutlineViewItem alloc] init];
					[child addObject:@"Destination Port"];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.ipdata.payload.tcphdr.dport];
					[child addObject:str];
					[str release];
					[ret addChild:child];
					[child release];

					/* TCP seq. no. child */
					child = [[OutlineViewItem alloc] init];
					[child addObject:@"Sequence Number"];
					str = [[NSString alloc] initWithFormat:@"%u", cont.lower.ipdata.payload.tcphdr.seq];
					[child addObject:str];
					[str release];
					[ret addChild:child];
					[child release];
				} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_UDP)
					return cont.lower.ipdata.payload.udpdec;
			} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP) {
				ret = [[OutlineViewItem alloc] init];
				[ret addObject:names[10][0]];
				str = [[NSString alloc] initWithFormat:@"%u", cont.lower.tstamp.trans];
				[ret addObject:str];
				[str release];
			}
			break;

		case 7:
			if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ && (fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP) {
				ret = [[OutlineViewItem alloc] init];
				[ret addObject:names[10][0]];
				str = [[NSString alloc] initWithFormat:@"%u", cont.lower.tstamp.trans];
				[ret addObject:str];
				[str release];
			}
			break;
	}

	return [ret autorelease];
}

- (size_t)numberOfValues
{
	return 1;
}

- (id)valueAtIndex:(int)anIndex
{
	return [[self class] longName];
}

- (BOOL)isChecksumValid
{
	return (sum == 0 || sum == [self computedChecksum]);
}

- (uint16_t)computedChecksum
{
	NSData *data;
	IPV4Decode *ip;
	struct icmp *hdr;
	size_t skip_bytes;
	size_t len;
	uint16_t saved_sum;

	if(calced_sum != 0)
		return calced_sum;

	if((ip = [parent decoderForClass:[IPV4Decode class]]) == nil)
		return 0;

	skip_bytes = [parent byteOffsetForDecoder:self];
	data = [parent packetData];

	if([data length] < skip_bytes || [data length] - skip_bytes < ICMPDECODE_HDR_MIN)
		return 0;

	hdr = (struct icmp *)((uint8_t *)[data bytes] + skip_bytes);

	saved_sum = hdr->icmp_cksum;
	hdr->icmp_cksum = 0;

	len = [ip length] - [ip headerLength];

	if(len > [data length] - skip_bytes)
		len = [data length] - skip_bytes;

	calced_sum = in_cksum_fold(in_cksum_partial(hdr, len, 0));

	hdr->icmp_cksum = saved_sum;

	return calced_sum;
}

/* Decodes IPv4 header + UDP or 8 bytes of TCP,
   Data should be the unmodified NSData object passed to ICMPDecode. */
- (void)decodeIPData:(NSData *)dataVal
{
	NSData *subip;

	subip = [[NSData alloc] initWithBytesNoCopy:(uint8_t *)[dataVal bytes] + ICMP_MINLEN
							length:[dataVal length] - ICMP_MINLEN
							freeWhenDone:NO];

	if((cont.lower.ipdata.ipdec = [[IPV4Decode alloc] initWithData:subip parent:self]) != nil) {
		frontSize += [cont.lower.ipdata.ipdec frontSize];
		fields |= ICMPDECODE_IP;
		if([cont.lower.ipdata.ipdec nextLayer] == [UDPDecode class]) {
			NSData *subudp;

			if((subudp = [[NSData alloc] initWithBytesNoCopy:(uint8_t *)[subip bytes] + [cont.lower.ipdata.ipdec frontSize]
										 length:[subip length] - [cont.lower.ipdata.ipdec frontSize]
										 freeWhenDone:NO]) == nil) {
				[subip release];
				return;
			}
			if((cont.lower.ipdata.payload.udpdec = [[UDPDecode alloc] initWithData:subudp parent:self]) != nil) {
				fields |= ICMPDECODE_UDP;
				frontSize += UDPDECODE_HDR_MIN;
			}
			[subudp release];
		} else if([cont.lower.ipdata.ipdec nextLayer] == [TCPDecode class] &&
				([subip length] - [cont.lower.ipdata.ipdec frontSize]) >= 8) {
			cont.lower.ipdata.payload.tcphdr = *(struct minitcp *)((uint8_t *)[subip bytes] + [cont.lower.ipdata.ipdec frontSize]);
			fields |= ICMPDECODE_TCP;
			frontSize += 8; /* UDP is always 8 octets */
		}
	}
	[subip release];
}

/* NSCoding protocol methods */

- (void)encodeWithCoder:(NSCoder *)coder
{
	[coder encodeValueOfObjCType:@encode(unsigned char) at:&fields];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&type];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&code];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&sum];

	if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ)
		[coder encodeValueOfObjCType:@encode(struct idseq) at:&cont.upper.idseq];
	else if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_GWADDR)
		[coder encodeValueOfObjCType:@encode(struct in_addr) at:&cont.upper.gateway];
	else if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_PARAMPTR)
		[coder encodeValueOfObjCType:@encode(uint8_t) at:&cont.upper.pptr];

	if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_SUBMASK)
		[coder encodeValueOfObjCType:@encode(uint32_t) at:&cont.lower.mask];
	else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP)
		[coder encodeValueOfObjCType:@encode(struct tstamp) at:&cont.lower.tstamp];
	else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_IP)
		[coder encodeObject:cont.lower.ipdata.ipdec];
	else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_UDP) {
		[coder encodeObject:cont.lower.ipdata.ipdec];
		[coder encodeObject:cont.lower.ipdata.payload.udpdec];
	} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TCP) {
		[coder encodeObject:cont.lower.ipdata.ipdec];
		[coder encodeValueOfObjCType:@encode(struct minitcp) at:&cont.lower.ipdata.payload.tcphdr];
	}

}

- (id)initWithCoder:(NSCoder *)coder
{
	if((self = [super init]) != nil) {
		[coder decodeValueOfObjCType:@encode(unsigned char) at:&fields];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&type];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&code];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&sum];

		if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_IDSEQ)
			[coder decodeValueOfObjCType:@encode(struct idseq) at:&cont.upper.idseq];
		else if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_GWADDR)
			[coder decodeValueOfObjCType:@encode(struct in_addr) at:&cont.upper.gateway];
		else if((fields & ICMPDECODE_UPPERMASK) == ICMPDECODE_PARAMPTR)
			[coder decodeValueOfObjCType:@encode(uint8_t) at:&cont.upper.pptr];

		if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_SUBMASK)
			[coder decodeValueOfObjCType:@encode(uint32_t) at:&cont.lower.mask];
		else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TSTAMP)
			[coder decodeValueOfObjCType:@encode(struct tstamp) at:&cont.lower.tstamp];
		else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_IP)
			cont.lower.ipdata.ipdec = [[coder decodeObject] retain];
		else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_UDP) {
			cont.lower.ipdata.ipdec = [[coder decodeObject] retain];
			cont.lower.ipdata.payload.udpdec = [[coder decodeObject] retain];
		} else if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_TCP) {
			cont.lower.ipdata.ipdec = [[coder decodeObject] retain];
			[coder decodeValueOfObjCType:@encode(struct minitcp) at:&cont.lower.ipdata.payload.tcphdr];
		}
		calced_sum = 0;
		frontSize = 0;
		parent = nil;
	}
	return self;
}

/* PPDecoderParent methods */

- (HostCache *)hostCache
{
	return [parent hostCache];
}

- (NSData *)dataForDecoder:(id)decoder
{
	NSData *data;
	size_t offset;

	data = [self packetData];
	offset = [self byteOffsetForDecoder:decoder];

	return [NSData dataWithBytesNoCopy:((uint8_t *)[data bytes] + offset)
				   length:([data length] - offset)
				   freeWhenDone:NO];
}

- (size_t)byteOffsetForDecoder:(id)decoder
{
	if(fields & ICMPDECODE_IP && cont.lower.ipdata.ipdec == decoder)
		return 0;

	if(fields & ICMPDECODE_IP &&
	   fields & ICMPDECODE_UDP &&
	   cont.lower.ipdata.payload.udpdec == decoder) {
		/* fontSize was verified in decodeIPData */
		return [cont.lower.ipdata.ipdec frontSize];
	}

	return 0;
}

- (id)decoderForClass:(Class)aClass
{
	if(aClass == [IPV4Decode class]) {
		if(fields & ICMPDECODE_IP)
			return cont.lower.ipdata.ipdec;
	} else if(aClass == [UDPDecode class]) {
		if(fields & ICMPDECODE_UDP)
			return cont.lower.ipdata.payload.udpdec;
	}

	return nil;
}

- (NSArray *)decoders
{
	if(fields & ICMPDECODE_IP)
		return [NSArray arrayWithObject:cont.lower.ipdata.ipdec];
	if(fields & ICMPDECODE_IP && fields & ICMPDECODE_UDP)
		return [NSArray arrayWithObjects:cont.lower.ipdata.ipdec,
										 cont.lower.ipdata.payload.udpdec, nil];
	return nil;
}

- (NSData *)packetData
{
	NSData *data;

	if((data = [parent dataForDecoder:self]) == nil)
		return nil;

	return [NSData dataWithBytesNoCopy:(uint8_t *)[data bytes] + ICMP_MINLEN
				   length:[data length] - ICMP_MINLEN
				   freeWhenDone:NO];
}

- (uint32_t)captureLength
{
	return (uint32_t)[[self packetData] length];
}

- (uint32_t)actualLength
{
	return (uint32_t)[[self packetData] length];
}

- (NSDate *)date
{
	return [parent date];
}

- (void)dealloc
{
	if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_IP)
		[cont.lower.ipdata.ipdec release];
	if((fields & ICMPDECODE_LOWERMASK) == ICMPDECODE_UDP) {
		[cont.lower.ipdata.ipdec release];
		[cont.lower.ipdata.payload.udpdec release];
	}
	[super dealloc];
}

@end
