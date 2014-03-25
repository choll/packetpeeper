/*
 * Packet Peeper
 * Copyright 2006, 2007, Chris E. Holloway
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
#include <machine/endian.h>
#include <stdlib.h>
#include <string.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#import <Foundation/NSHost.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSArchiver.h>
#include "Packet.h"
#include "PPPluginManager.h"
#include "PPDecoderPlugin.h"
#include "ICMPDecode.h"
#include "UDPDecode.h"
#include "TCPDecode.h"
#include "HostCache.h"
#include "ColumnIdentifier.h"
#include "strfuncs.h"
#include "pkt_compare.h"
#include "in_cksum.h"
#include "IPV4Decode.h"

static NSString *names[][2] =	{{@"Version", @"IPv4 Ver"},
								{@"Header length", @"IPv4 Hdr Len"},
								{@"Type of service", @"IPv4 TOS"},
								{@"Total length", @"IPv4 Len"},
								{@"Identification", @"IPv4 Ident"},
								{@"Flags", @"IPv4 Flags"},
								{@"Fragment Offset", @"IPv4 Frag"},
								{@"Time To Live", @"IPv4 TTL"},
								{@"Protocol Type", @"IPv4 Proto"},
								{@"Checksum", @"IPv4 Cksum"},
								{@"Source IP Address", @"Src IP"},
								{@"Destination IP Address", @"Dst IP"},
								{@"Options", @"IPv4 Options"},
								{@"Source Hostname", @"Src Host"},
								{@"Destination Hostname", @"Dst Host"},
								{@"Flags Meaning", @"IPv4 Flags *"}};

#define IPV4DECODE_LENGTH		3
#define IPV4DECODE_IPHOST_SRC	14
#define IPV4DECODE_IPHOST_DST	15

@implementation IPV4Decode

- (id)initWithData:(NSData *)dataVal parent:(id <PPDecoderParent>)parentVal
{
	struct ip *hdr;

	if(dataVal == nil)
		return nil;

	if((self = [super init]) != nil) {
		parent = parentVal;

		if([dataVal length] < IPV4DECODE_HDR_MIN)
			goto err;

		/* n.b. all fields in network byte order (so convert anything 2 WHOLE bytes or more) */
		hdr = (struct ip *)[dataVal bytes];

		/* perhaps just note to the user that this is invalid, process no options
		   and set nextLayer to Nil. */
		if(hdr->ip_hl < 5 || (hdr->ip_hl * 4) > [dataVal length])
			goto err;

		version = hdr->ip_v;
		hlen = hdr->ip_hl;
		tos = hdr->ip_tos;
		tlen = ntohs(hdr->ip_len);
		ident = ntohs(hdr->ip_id);
//#if (BYTE_ORDER == BIG_ENDIAN)
		flags = (hdr->ip_off & ~IP_OFFMASK) >> 8;
//#elif (BYTE_ORDER == LITTLE_ENDIAN)
//		flags = (hdr->ip_off & ~IP_OFFMASK) >> 13;
//#else
//#error "Unknown byte order"
//#endif
		offset = ntohs(hdr->ip_off & IP_OFFMASK);
		ttl = hdr->ip_ttl;
		proto = hdr->ip_p;
		sum = hdr->ip_sum;
		calced_sum = 0;
		src = hdr->ip_src;
		dst = hdr->ip_dst;
		optionsDecoder = nil;

#if 0
		next_opt = &opts_list;

		/* process ip options */
		if(hlen > 5) {
			unsigned int nbytes;	/* bytes available to process */
			const uint8_t *opts;	/* pointer to options */

			nbytes = MIN((hdr->ip_hl * 4) - IPV4DECODE_HDR_MIN, [dataVal length] - IPV4DECODE_HDR_MIN);
			opts = (uint8_t *)[dataVal bytes] + IPV4DECODE_HDR_MIN;

			while(nbytes > 0) {
				switch(*opts) {
					/* no operation */
					case IPOPT_NOP:
						if((*next_opt = malloc(sizeof(struct option))) == NULL)
							goto end_opts;

						(*next_opt)->type = OPTION_NOP;
						next_opt = &(*next_opt)->next;

						--nbytes;
						++opts;
						break;

					/* security options as per RFC 791 (TODO, RFC 1108 security options?) */
					case IPOPT_SECURITY:
						/* check for valid length */
						if(nbytes < 11 || opts[1] != 11)
							goto end_opts;

						if((*next_opt = malloc(sizeof(struct option_security))) == NULL)
							goto end_opts;

						(*next_opt)->type = OPTION_SECURITY;

						switch(*(uint16_t *)(opts + 2)) {
							case IPOPT_SECUR_UNCLASS:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_UNCLASSIFIED;
								break;

							case IPOPT_SECUR_CONFID:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_CONFIDENTIAL;
								break;

							case IPOPT_SECUR_EFTO:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_EFTO;
								break;

							case IPOPT_SECUR_MMMM:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_MMMM;
								break;

							case IPOPT_SECUR_PROG:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_PROG;
								break;

							case IPOPT_SECUR_RESTR:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_RESTRICTED;
								break;

							case IPOPT_SECUR_SECRET:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_SECRET;
								break;

							case IPOPT_SECUR_TOPSECRET:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_TOPSECRET;
								break;

							default:
								((struct option_security *)*next_opt)->level = OPTION_SECURITY_UNKNOWN;
								break;
						}

						((struct option_security *)*next_opt)->compartment = *(uint16_t *)(opts + 4);
						((struct option_security *)*next_opt)->restrictions = *(uint16_t *)(opts + 6);
						((struct option_security *)*next_opt)->control = (*(uint32_t *)(opts + 8)) & 0xFFFFFF;
						next_opt = &(*next_opt)->next;

						nbytes -= 11;
						opts += 11;
						break;

					case IPOPT_LSRR:	/* loose source and record route */
					case IPOPT_SSRR:	/* strict source and record route */
					case IPOPT_RR:		/* record route */
						/* we expect there to be at least space for one address (4+3) */
						if(nbytes < 7 || nbytes < opts[1])
							goto end_opts;

						/* sanity check, pointer should never be more than
						   one greater than the option length, should be at
						   least 4, and should be divisible by 4. */
						if(opts[2] > (opts[1] + 1) || opts[2] < 4 || (opts[2] % 4) != 0)
							goto end_opts;

						{
							unsigned int n;

							/* number of in_addrs in the option */
							n = ((opts[2] - 3) / 4);

							if((*next_opt = malloc(sizeof(struct option_route) + (sizeof(struct in_addr) * n))) == NULL)
								goto end_opts;

							if(*opts == IPOPT_LSRR)
								(*next_opt)->type = OPTION_LOOSE_SRC_REC_ROUTE;
							else if(*opts == IPOPT_SSRR)
								(*next_opt)->type = OPTION_STRICT_SRC_REC_ROUTE;
							else
								(*next_opt)->type = OPTION_REC_ROUTE;

							((struct option_route *)*next_opt)->n_addrs = n;

							memcpy(((struct option_route *)*next_opt)->addr, opts + 3, opts[2] - 3);

							next_opt = &(*next_opt)->next;

							nbytes -= opts[1];
							opts += opts[1];
						}
						break;

					/* SATNET stream id */
					case IPOPT_SATID:
						/* check for valid length */
						if(nbytes < 4 || opts[1] != 4)
							goto end_opts;

						if((*next_opt = malloc(sizeof(struct option_stream_id))) == NULL)
							goto end_opts;

						(*next_opt)->type = OPTION_STREAM_ID;
						((struct option_stream_id *)*next_opt)->stream_id = *(uint16_t *)(opts + 2);
						next_opt = &(*next_opt)->next;

						nbytes -= 4;
						opts += 4;
						break;

					/* timestamp */
					case IPOPT_TS:
						if(nbytes < 8 || nbytes < opts[1] || opts[1] > 40)
							goto end_opts;

						/* sanity check, pointer should never be more than
						   one greater than the option length, should be at
						   least 5, and should be divisible by 4. */
						if(opts[2] > (opts[1] + 1) || opts[2] < 5 || ((opts[2] - 5) % 4) != 0)
							goto end_opts;

						{
							struct ip_timestamp *ts;
							unsigned int nelems;
							size_t nbytes;

							ts = (struct ip_timestamp *)opts;

							if(ts->ipt_flg != IPOPT_TS_TSONLY &&
							   ts->ipt_flg != IPOPT_TS_TSANDADDR &&
							   ts->ipt_flg != IPOPT_TS_PRESPEC)
								goto end_opts;

							if(ts->ipt_flg == IPOPT_TS_TSONLY) {
								nelems = (ts->ipt_len - 4) / sizeof(uint32_t);
								nbytes = sizeof(struct option_timestamp_tso) + (ts->ipt_len - 4);
							} else {
								nelems = (ts->ipt_len - 4) / (sizeof(struct in_addr) + sizeof(uint32_t));
								nbytes = sizeof(struct option_timestamp_tsa) + (ts->ipt_len - 4);
							}

							if((*next_opt = malloc(nbytes)) == NULL)
								goto end_opts;

							(*next_opt)->type = OPTION_TIMESTAMP;
							((struct option_timestamp_tso *)*next_opt)->overflow = ts->ipt_oflw;
							((struct option_timestamp_tso *)*next_opt)->flags = ts->ipt_flg;
							((struct option_timestamp_tso *)*next_opt)->nelems = nelems;

							if(ts->ipt_flg == IPOPT_TS_TSONLY)
								memcpy(((struct option_timestamp_tso *)*next_opt)->usecs, opts + 4, ts->ipt_len - 4);
							else
								memcpy(((struct option_timestamp_tsa *)*next_opt)->tsa, opts + 4, ts->ipt_len - 4);

							next_opt = &(*next_opt)->next;

							nbytes -= opts[1];
							opts += opts[1];
						}
						break;

					/* router alert */
					//case IPOPT_RA:
					//	break;	which rfc?

					/* traceroute, see rfc 1393 */

					/* end of option list */
					case IPOPT_EOL:
					default:
						goto end_opts;
				}
			}
		}
		end_opts:
			*next_opt = NULL;
#endif
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

- (unsigned int)frontSize
{
	return hlen * 4;	/* hlen is measured in 32bit words, maximum value is 60 */
}

- (unsigned int)rearSize
{
	return 0;
}

- (Class)nextLayer
{
	switch(proto) {
		case IPPROTO_ICMP:
			return [ICMPDecode class];
			/* NOTREACHED */

//		case IPPROTO_IGMP:
//			nextLayer = [IGMPDecode class]
//			break;

		case IPPROTO_TCP:
			return [TCPDecode class];
			/* NOTREACHED */

		case IPPROTO_UDP:
			return [UDPDecode class];
			/* NOTREACHED */
	}
	return Nil;
}

+ (NSString *)shortName
{
	return @"IPv4";
}

+ (NSString *)longName
{
	return @"IP Version 4";
}

- (NSString *)info
{
	return [NSString stringWithFormat:@"%@ to %@, %uB total%s", [self from], [self to], tlen, [self isChecksumValid] ? "" : " (bad checksum)"];
}

- (NSString *)addrTo
{
	return ipaddrstr(&dst, sizeof(dst));
}

- (NSString *)addrFrom
{
	return ipaddrstr(&src, sizeof(src));
}

- (NSString *)resolvTo
{
	return [[parent hostCache] hostWithAddressASync:&dst returnCode:NULL];
}

- (NSString *)resolvFrom
{
	return [[parent hostCache] hostWithAddressASync:&src returnCode:NULL];
}

- (NSString *)to
{
	NSString *ret;

	if((ret = [self resolvTo]) == nil)
		ret = [self addrTo];

	return ret;
}

- (NSString *)from
{
	NSString *ret;

	if((ret = [self resolvFrom]) == nil)
		ret = [self addrFrom];

	return ret;
}

- (uint8_t)protocol
{
	return proto;
}

- (BOOL)isChecksumValid
{
	return (sum == 0 || sum == [self computedChecksum]);
}

- (uint16_t)computedChecksum
{
	NSData *data;
	struct ip *hdr;
	size_t skip_bytes;
	size_t hdr_nbytes;
	uint16_t saved_sum;

	if(calced_sum != 0)
		return calced_sum;

	skip_bytes = [parent byteOffsetForDecoder:self];
	data = [parent packetData];

	if([data length] < skip_bytes || [data length] - skip_bytes < IPV4DECODE_HDR_MIN)
		return 0;

	hdr = (struct ip *)((uint8_t *)[data bytes] + skip_bytes);

	hdr_nbytes = hdr->ip_hl * 4;

	if([data length] - skip_bytes < hdr_nbytes)
		return 0;

	saved_sum = hdr->ip_sum;
	hdr->ip_sum = 0;

	calced_sum = in_cksum_fold(in_cksum_partial(hdr, hdr_nbytes, 0));

	hdr->ip_sum = saved_sum;

	return calced_sum;
}

- (NSString *)flagsMeaning
{
	NSString *flag_names[] = {@"Reserved", @"Don't Fragment", @"More Fragments"};
	NSMutableString *ret;
	unsigned int i;

	ret = nil;

	for(i = 0; i < (sizeof(flag_names) / sizeof(flag_names[0])); ++i) {
		if(flags & (1 << (7 - i))) {
			if(ret == nil)
				ret = [[NSMutableString alloc] initWithString:flag_names[i]];
			else
				[ret appendFormat:@", %@", flag_names[i]];
		}
	}

	if(ret == nil)
		return @"None";

	return [ret autorelease];
}

- (BOOL)dontFragmentFlag
{
	return (flags & IPV4DECODE_FLAGS_DFRAG) != 0;
}

- (BOOL)moreFragmentsFlag
{
	return (flags & IPV4DECODE_FLAGS_MFRAG) != 0;
}

- (unsigned int)fragmentOffset
{
	return offset;
}

- (unsigned int)length
{
	return tlen;
}

- (unsigned int)headerLength
{
	return hlen * 4;
}

- (struct in_addr)in_addrSrc
{
	return src;
}

- (struct in_addr)in_addrDst
{
	return dst;
}

- (NSData *)optionsData
{
	NSData *data;
	size_t nbytes;

	if((data = [parent dataForDecoder:self]) == nil)
		return nil;

	if([data length] <= IPV4DECODE_HDR_MIN)
		return nil;

	nbytes = (hlen * 4) - IPV4DECODE_HDR_MIN;

	if([data length] < nbytes)
		nbytes = [data length];

	return [NSData dataWithBytesNoCopy:((uint8_t *)[data bytes] + IPV4DECODE_HDR_MIN)
				   length:nbytes freeWhenDone:NO];
}

- (id <OutlineViewItem>)resolvCallback:(void *)data
{
	OutlineViewItem *ret;
	NSString *resolved;
	int retcode;

	ret = [[OutlineViewItem alloc] init];

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

	return [ret autorelease];
}

- (stacklev)level
{
	return SL_NETWORK;
}

- (NSString *)description
{
	return [NSString stringWithFormat:@"[IP: %@ to %@]", [self from], [self to]];
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
			return [NSString stringWithFormat:@"%u", version];
			/* NOTREACHED */

		case 1:
			return [NSString stringWithFormat:@"%u (%u B)", hlen, hlen * 4];
			/* NOTREACHED */

		case 2:
			return [NSString stringWithFormat:@"0x%.2x", tos];
			/* NOTREACHED */

		case 3:
			return [NSString stringWithFormat:@"%u B", tlen];
			/* NOTREACHED */

		case 4:
			return [NSString stringWithFormat:@"%u", ident];
			/* NOTREACHED */

		case 5:
			return binstr(&flags, 3);
			/* NOTREACHED */

		case 6:
			return [NSString stringWithFormat:@"%u (%u B)", offset, offset * 8];
			/* NOTREACHED */

		case 7:
			return [NSString stringWithFormat:@"%u hop(s)", ttl];
			/* NOTREACHED */

		case 8:
			/* needs to be looked up */
			return [NSString stringWithFormat:@"0x%.2x", proto];
			/* NOTREACHED */

		case 9:
			return [NSString stringWithFormat:@"0x%.4x", sum];
			/* NOTREACHED */

		case 10:
			return [self addrFrom];
			/* NOTREACHED */

		case 11:
			return [self addrTo];
			/* NOTREACHED */

		case 12:
			return (hlen > 5) ? @"Yes" : @"No";
			/* NOTREACHED */

		case 13:
			return [self from];
			/* NOTREACHED */

		case 14:
			return [self to];
			/* NOTREACHED */

		case 15:
			return [self flagsMeaning];
			/* NOTREACHED */
	}

	return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
	switch(fieldIndex) {
		case 0:
			return val_compare(version, ((IPV4Decode *)obj)->version);

		case 1:
			return val_compare(hlen, ((IPV4Decode *)obj)->hlen);

		case 2:
			return val_compare(tos, ((IPV4Decode *)obj)->tos);

		case 3:
			return val_compare(tlen, ((IPV4Decode *)obj)->tlen);

		case 4:
			return val_compare(ident, ((IPV4Decode *)obj)->ident);

		case 5:
			return val_compare(flags, ((IPV4Decode *)obj)->flags);

		case 6:
			return val_compare(offset, ((IPV4Decode *)obj)->offset);

		case 7:
			return val_compare(ttl, ((IPV4Decode *)obj)->ttl);

		case 8:
			return val_compare(proto, ((IPV4Decode *)obj)->proto);

		case 9:
			return val_compare(sum, ((IPV4Decode *)obj)->sum);

		case 10:
			return mem_compare(&src, &(((IPV4Decode *)obj)->src), sizeof(src));

		case 11:
			return mem_compare(&dst, &(((IPV4Decode *)obj)->dst), sizeof(dst));

		case 12:
			return val_compare((hlen > 5) ? 1 : 0, (((IPV4Decode *)obj)->hlen > 5) ? 1 : 0);

		case 13:
			return [[self resolvFrom] compare:[obj resolvFrom]];

		case 14:
			return [[self resolvTo] compare:[obj resolvTo]];

		case 15:
			return [[self flagsMeaning] compare:[obj flagsMeaning]];
	}

	return NSOrderedSame;
}

/* OutlineView protocol methods */

- (BOOL)expandable
{
	return YES;
}

- (unsigned int)numberOfChildren
{
	return 12 + ((hlen > 5) ? 1 : 0);
}

- (id)childAtIndex:(int)fieldIndex
{
	OutlineViewItem *ret;
	NSString *str;

	if(fieldIndex == 12) { /* options sub-decoder */
		if(optionsDecoder == nil) {
			if((optionsDecoder = [[PPPluginManager sharedPluginManager] pluginWithLongName:@"IPv4 Options"]) == nil)
				return nil;
			[optionsDecoder retain];
		}
		return [optionsDecoder outlineViewItemTreeForData:[self optionsData]];
	}

	ret = [[OutlineViewItem alloc] init];
	[ret addObject:names[fieldIndex][0]];

	switch(fieldIndex) {
		case 0:
			str = [[NSString alloc] initWithFormat:@"%u", version];
			[ret addObject:str];
			[str release];
			break;

		case 1:
			str = [[NSString alloc] initWithFormat:@"%u (%u Bytes)", hlen, hlen * 4];
			[ret addObject:str];
			[str release];
			break;

		case 2:
			/* needs to be expandable */
			str = [[NSString alloc] initWithFormat:@"0x%.2x", tos];
			[ret addObject:str];
			[str release];

			// [ret addChildWithObjects:a, b, nil];
			// addChildWithObjects
			// addChildWithObjects

			//IPTOS_LOWDELAY
			//IPTOS_THROUGHPUT
			//IPTOS_RELIABILITY
			//IPTOS_MINCOST

			//IPTOS_CE
			//IPTOS_ECT

			break;

		case 3:
			/* possibly verify this, i.e inform the user if the length is wrong */
			str = [[NSString alloc] initWithFormat:@"%u Byte(s)", tlen];
			[ret addObject:str];
			[str release];
			break;

		case 4:
			str = [[NSString alloc] initWithFormat:@"%u", ident];
			[ret addObject:str];
			[str release];
			break;

		case 5:
			[ret addObject:[NSString stringWithFormat:@"%@ (%@)", binstr(&flags, 3), [self flagsMeaning]]];
			[ret addChildWithObjects:[NSString stringWithFormat:@"Reserved"],
									 [NSString stringWithFormat:@"%s", (flags & IPV4DECODE_FLAGS_RES) ? "Yes" : "No"], nil];
			[ret addChildWithObjects:[NSString stringWithFormat:@"Don't fragment"],
									 [NSString stringWithFormat:@"%s", (flags & IPV4DECODE_FLAGS_DFRAG) ? "Yes" : "No"], nil];
			[ret addChildWithObjects:[NSString stringWithFormat:@"More fragments"],
									 [NSString stringWithFormat:@"%s", (flags & IPV4DECODE_FLAGS_MFRAG) ? "Yes" : "No"], nil];
			break;

		case 6:
			str = [[NSString alloc] initWithFormat:@"%u (%u Bytes)", offset, offset * 8];
			[ret addObject:str];
			[str release];
			break;

		case 7:
			str = [[NSString alloc] initWithFormat:@"%u Hop%s", ttl, (ttl != 1) ? "s" : ""];
			[ret addObject:str];
			[str release];
			break;

		case 8:
			/* needs to be looked up */
			str = [[NSString alloc] initWithFormat:@"0x%.2x", proto];
			[ret addObject:str];
			[str release];
			break;

		case 9:
			if(sum == [self computedChecksum])
				str = [[NSString alloc] initWithFormat:@"0x%.4x (correct)", sum];
			else
				str = [[NSString alloc] initWithFormat:@"0x%.4x (incorrect, should be 0x%.4x)", sum, [self computedChecksum]];
			[ret addObject:str];
			[str release];
			break;

		case 10:
			[ret addObject:[self addrFrom]];
			[ret addChildWithCallback:self selector:@selector(resolvCallback:) data:&src];
			break;

		case 11:
			[ret addObject:[self addrTo]];
			[ret addChildWithCallback:self selector:@selector(resolvCallback:) data:&dst];
			break;

#if 0
		case 12: /* options */
			{ 
				struct option *cur;
				OutlineViewItem *item;
				unsigned int i;

				for(cur = opts_list, i = 0; cur != NULL; cur = cur->next, ++i) {
					if(i == (index - 12))
						break;
				}

				switch(cur->type) {
					case OPTION_NOP:
						[ret addChildWithObjects:@"No operation", nil];
						break;

					case OPTION_SECURITY:
						[ret addChildWithObjects:@"Security", nil];
						break;

					case OPTION_STREAM_ID:
						str = [[NSString alloc] initWithFormat:@"%u", ((struct option_stream_id *)cur)->stream_id];
						[ret addChildWithObjects:@"Stream ID", str, nil];
						[str release];
						break;

					case OPTION_LOOSE_SRC_REC_ROUTE:
					case OPTION_STRICT_SRC_REC_ROUTE:
					case OPTION_REC_ROUTE:
						if(cur->type == OPTION_LOOSE_SRC_REC_ROUTE)
							item = [OutlineViewItem outlineViewWithObject:@"Loose source record route"];
						else if(cur->type == OPTION_STRICT_SRC_REC_ROUTE)
							item = [OutlineViewItem outlineViewWithObject:@"Strict source record route"];
						else
							item = [OutlineViewItem outlineViewWithObject:@"Record route"];

						for(i = 0; i < ((struct option_route *)cur)->n_addrs; ++i) {
							OutlineViewItem *subitem;

							if((subitem = [[OutlineViewItem alloc] init]) == nil)
								break;

							str = [[NSString alloc] initWithFormat:@"IP Address %u", i + 1];
							[subitem addObject:str];
							[str release];
							[subitem addObject:ipaddrstr(&(((struct option_route *)cur)->addr[i]), sizeof(struct in_addr))];

									/* need to add another child to subitem, except
									   how will the callback work? will need to pass some data
									   into the callback. which really will be better,
									   cuz we can pass the actuall address... */

							[item addChild:subitem];
							[subitem release];
						}

						if(i == 0)
							[item addObject:@"No addresses"];

						[ret addChild:item];
						break;

					case OPTION_TIMESTAMP:
						[ret addChildWithObjects:@"Timestamp", nil];
						break;
				}
			}
			break;
#endif
		default:
			[ret release];
			return nil;
	}

	return [ret autorelease];
}

- (unsigned int)numberOfValues
{
	return 1;
}

- (id)valueAtIndex:(int)anIndex
{
	return [[self class] longName];
}

- (void)encodeWithCoder:(NSCoder *)coder
{
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&version];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&hlen];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&tos];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&tlen];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&ident];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&flags];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&offset];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&ttl];
	[coder encodeValueOfObjCType:@encode(uint8_t) at:&proto];
	[coder encodeValueOfObjCType:@encode(uint16_t) at:&sum];
	[coder encodeValueOfObjCType:@encode(struct in_addr) at:&src];
	[coder encodeValueOfObjCType:@encode(struct in_addr) at:&dst];

#if 0
	if(hlen > 5) {
		struct option *opts;
		uint8_t type;

		for(opts = opts_list; opts != NULL; opts = opts->next) {
			[coder encodeValueOfObjCType:@encode(uint8_t) at:&opts->type];

			switch(opts->type) {
				case OPTION_NOP:
					break;

				case OPTION_SECURITY:
					[coder encodeArrayOfObjCType:@encode(uint8_t) count:9 at:&((struct option_security *)opts)->level];
					break;

				case OPTION_STREAM_ID:
					[coder encodeValueOfObjCType:@encode(uint16_t) at:&((struct option_stream_id *)opts)->stream_id];
					break;

				case OPTION_LOOSE_SRC_REC_ROUTE:
				case OPTION_STRICT_SRC_REC_ROUTE:
				case OPTION_REC_ROUTE:
					[coder encodeValueOfObjCType:@encode(uint8_t) at:&((struct option_route *)opts)->n_addrs];
					[coder encodeArrayOfObjCType:@encode(struct in_addr) count:((struct option_route *)opts)->n_addrs at:&((struct option_route *)opts)->addr];
					break;

				case OPTION_TIMESTAMP:
					[coder encodeArrayOfObjCType:@encode(uint8_t) count:3 at:&((struct option_timestamp_tso *)opts)->nelems];

					if(((struct option_timestamp_tso *)opts)->flags == IPOPT_TS_TSONLY)
						[coder encodeArrayOfObjCType:@encode(uint32_t) count:((struct option_timestamp_tso *)opts)->nelems at:&((struct option_timestamp_tso *)opts)->usecs];
					else
						[coder encodeArrayOfObjCType:@encode(struct tsa) count:((struct option_timestamp_tsa *)opts)->nelems at:&((struct option_timestamp_tsa *)opts)->tsa];
					break;
			}
		}

		type = OPTION_END;
		[coder encodeValueOfObjCType:@encode(uint8_t) at:&type];
	}
#endif

}

- (id)initWithCoder:(NSCoder *)coder
{
	if((self = [super init]) != nil) {
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&version];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&hlen];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&tos];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&tlen];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&ident];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&flags];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&offset];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&ttl];
		[coder decodeValueOfObjCType:@encode(uint8_t) at:&proto];
		[coder decodeValueOfObjCType:@encode(uint16_t) at:&sum];
		[coder decodeValueOfObjCType:@encode(struct in_addr) at:&src];
		[coder decodeValueOfObjCType:@encode(struct in_addr) at:&dst];
		calced_sum = 0;
		parent = nil;
		optionsDecoder = nil;

#if 0
		next_opt = &opts_list;

		if(hlen > 5) {
			uint8_t type;

			[coder decodeValueOfObjCType:@encode(uint8_t) at:&type];

			while(type != OPTION_END) {
				switch(type) {
					case OPTION_NOP:
						if((*next_opt = malloc(sizeof(struct option))) == NULL)
							goto end_opts;
						break;

					case OPTION_SECURITY:
						if((*next_opt = malloc(sizeof(struct option_security))) == NULL)
							goto end_opts;

						[coder decodeArrayOfObjCType:@encode(uint8_t) count:9 at:&((struct option_security *)*next_opt)->level];
						break;

					case OPTION_STREAM_ID:
						if((*next_opt = malloc(sizeof(struct option_stream_id))) == NULL)
							goto end_opts;

						[coder decodeValueOfObjCType:@encode(uint16_t) at:&((struct option_stream_id *)*next_opt)->stream_id];
						break;

					case OPTION_LOOSE_SRC_REC_ROUTE:
					case OPTION_STRICT_SRC_REC_ROUTE:
					case OPTION_REC_ROUTE:
						{
							uint8_t n_addrs;

							[coder decodeValueOfObjCType:@encode(uint8_t) at:&n_addrs];

							if((*next_opt = malloc(sizeof(struct option_route) + (sizeof(struct in_addr) * n_addrs))) == NULL)
								goto end_opts;

							((struct option_route *)*next_opt)->n_addrs = n_addrs;
							[coder decodeArrayOfObjCType:@encode(struct in_addr) count:n_addrs at:&((struct option_route *)*next_opt)->addr];
						}
						break;

					case OPTION_TIMESTAMP:
						{
							uint8_t nelems;
							uint8_t overflow;
							uint8_t ts_flags;
							size_t nbytes;

							[coder decodeValueOfObjCType:@encode(uint8_t) at:&nelems];
							[coder decodeValueOfObjCType:@encode(uint8_t) at:&overflow];
							[coder decodeValueOfObjCType:@encode(uint8_t) at:&ts_flags];

							if(ts_flags == IPOPT_TS_TSONLY)
								nbytes = sizeof(struct option_timestamp_tso) + (sizeof(uint32_t) * nelems);
							else
								nbytes = sizeof(struct option_timestamp_tsa) + (sizeof(struct tsa) * nelems);

							if((*next_opt = malloc(nbytes)) == NULL)
								goto end_opts;

							((struct option_timestamp_tso *)*next_opt)->nelems = nelems;
							((struct option_timestamp_tso *)*next_opt)->overflow = overflow;
							((struct option_timestamp_tso *)*next_opt)->flags = ts_flags;

							if(ts_flags == IPOPT_TS_TSONLY)
								[coder decodeArrayOfObjCType:@encode(uint32_t) count:nelems at:&((struct option_timestamp_tso *)*next_opt)->usecs];
							else
								[coder decodeArrayOfObjCType:@encode(struct tsa) count:nelems at:&((struct option_timestamp_tsa *)*next_opt)->tsa];
						}
						break;
				}

				(*next_opt)->type = type;
				next_opt = &(*next_opt)->next;
				[coder decodeValueOfObjCType:@encode(uint8_t) at:&type];
			}
		}
		end_opts:
			*next_opt = NULL;
#endif
	}
	return self;
}

- (void)dealloc
{
	//struct option *cur;
	[optionsDecoder release];

#if 0
	while(opts_list != NULL) {
		cur = opts_list;
		opts_list = opts_list->next;
		free(cur);
	}
#endif

	[super dealloc];
}

@end
