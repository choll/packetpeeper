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

#include "TCPDecode.h"
#include "IPV4Decode.h"
#include "IPV6Decode.h"
#include "Packet.h"
#include "PortCache.h"
#include "in_cksum.h"
#include "pkt_compare.h"
#import <Foundation/NSArchiver.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>

static NSString* names[][2] = {{@"Source Port", @"TCP Src Port"},
                               {@"Destination Port", @"TCP Dst Port"},
                               {@"Sequence Number", @"TCP Seq No."},
                               {@"Acknowledgment Number", @"TCP Ack No."},
                               {@"Header Length", @"TCP Hdr Len"},
                               {@"Flags", @"TCP Flags"},
                               {@"Window Size", @"TCP Win. Size"},
                               {@"Checksum", @"TCP Cksum"},
                               {@"Urgent Pointer", @"TCP Urg Ptr"},
                               {@"Payload Length", @"TCP Payload Len"},
                               {@"In Order", @"In Order"},
                               {@"Source Port Name", @"TCP Src Port *"},
                               {@"Destination Port Name", @"TCP Dst Port *"},
                               {@"Flags Meaning", @"TCP Flags *"}};

@implementation TCPDecode

- (id)initWithData:(NSData*)dataVal parent:(id<PPDecoderParent>)parentVal
{
    struct tcphdr* hdr;

    if (dataVal == nil)
        return nil;

    if ((self = [super init]) != nil)
    {
        if ([dataVal length] < TCPDECODE_HDR_MIN)
            goto err;

        parent = parentVal;

        hdr = (struct tcphdr*)[dataVal bytes];

        if (hdr->th_off < 5 || (hdr->th_off * 4) > [dataVal length])
            goto err;

        sport = ntohs(hdr->th_sport);
        dport = ntohs(hdr->th_dport);
        seq_no = ntohl(hdr->th_seq);
        ack_no = ntohl(hdr->th_ack);
        hlen = hdr->th_off;
        flags = hdr->th_flags;
        win_sz = ntohs(hdr->th_win);
        sum = hdr->th_sum;
        urg_ptr = ntohs(hdr->th_urp);

        size = UINT32_MAX;
        inOrder = NO;
        back_ptr = NULL;

        /* proccess options */
        if (hdr->th_off > 5)
        {
        }
    }
    return self;

err:
    [self dealloc];
    return nil;
}

- (void)setParent:(id<PPDecoderParent>)parentVal
{
    parent = parentVal;
}

- (size_t)frontSize
{
    return hlen *
           4; /* header length is measured in 32bit words, maximum value is 60 */
}

- (size_t)rearSize
{
    return 0;
}

- (Class)nextLayer
{
    return Nil;
}

+ (NSString*)shortName
{
    return @"TCP";
}

+ (NSString*)longName
{
    return @"TCP";
}

- (NSString*)info
{
    return [NSString
        stringWithFormat:@"%u to %u, [%@], S=%u, A=%u, %uB payload%s",
                         sport,
                         dport,
                         [self flagsStr],
                         seq_no,
                         ack_no,
                         [self size],
                         [self isChecksumValid] ? "" : " (bad checksum)"];
}

- (stacklev)level
{
    return SL_TRANSPORT;
}

- (NSString*)flagsStr
{
    NSString* flag_names[] = {
        @"FIN", @"SYN", @"RST", @"PSH", @"ACK", @"URG", @"ECE", @"CWR"};
    NSMutableString* ret;
    unsigned int i;

    ret = nil;

    for (i = 0; i < (sizeof(flag_names) / sizeof(flag_names[0])); ++i)
    {
        if (flags & (1 << i))
        {
            if (ret == nil)
                ret = [[NSMutableString alloc] initWithString:flag_names[i]];
            else
                [ret appendFormat:@", %@", flag_names[i]];
        }
    }

    if (ret == nil)
        return @"None";

    return [ret autorelease];
}

- (NSString*)srcPortName
{
    NSString* ret;

    ret = [[PortCache sharedPortCache] serviceWithTCPPort:sport];

    if (ret == nil)
        ret = [NSString stringWithFormat:@"%u", sport];

    return ret;
}

- (NSString*)dstPortName
{
    NSString* ret;

    ret = [[PortCache sharedPortCache] serviceWithTCPPort:dport];

    if (ret == nil)
        ret = [NSString stringWithFormat:@"%u", dport];

    return ret;
}

- (BOOL)isChecksumValid
{
    return (sum == 0 || sum == [self computedChecksum]);
}

- (uint16_t)computedChecksum
{
    NSData* data;
    NSArray* decoders;
    IPV4Decode* ip4 = nil;
    IPV6Decode* ip6 = nil;
    struct tcphdr* hdr;
    unsigned int i;
    unsigned int skip_bytes;
    unsigned int pseudo_hdr_nbytes;
    unsigned int partial_sum;
    uint16_t saved_sum;

    struct
    {
        struct in_addr src;
        struct in_addr dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } __attribute__((__packed__)) pseudo4_hdr;

    struct
    {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t proto;
    } __attribute__((__packed__)) pseudo6_hdr;

    void* pseudo_hdr = NULL;
    size_t pseudo_hdr_len = 0;

    if (calced_sum != 0)
        return calced_sum;

    if ((ip4 = [parent decoderForClass:[IPV4Decode class]]) == nil)
    {
        if ((ip6 = [parent decoderForClass:[IPV6Decode class]]) == nil)
            return 0;
    }

    if ((decoders = [parent decoders]) == nil)
        return 0;

    skip_bytes = 0;

    for (i = 0; i < [decoders count]; ++i)
    {
        id<Decode> current;
        if ((current = [decoders objectAtIndex:i]) == self)
            break;
        skip_bytes += [current frontSize];
    }

    data = [parent packetData];

    if ([data length] < skip_bytes ||
        [data length] - skip_bytes < TCPDECODE_HDR_MIN)
        return 0;

    hdr = (struct tcphdr*)((uint8_t*)[data bytes] + skip_bytes);
    saved_sum = hdr->th_sum;
    hdr->th_sum = 0;

    pseudo_hdr_nbytes = (self->hlen * 4) + [self size];

    if (ip4 != nil)
    {
        pseudo4_hdr.src = [ip4 in_addrSrc];
        pseudo4_hdr.dst = [ip4 in_addrDst];
        pseudo4_hdr.zero = 0;
        pseudo4_hdr.proto = IPPROTO_TCP;
        pseudo4_hdr.len = htons(pseudo_hdr_nbytes);
        pseudo_hdr = &pseudo4_hdr;
        pseudo_hdr_len = sizeof(pseudo4_hdr);
    }

    if (ip6 != nil)
    {
        pseudo6_hdr.src = [ip6 in6_addrSrc];
        pseudo6_hdr.dst = [ip6 in6_addrDst];
        pseudo6_hdr.len = htonl(pseudo_hdr_nbytes);
        pseudo6_hdr.zero[0] = pseudo6_hdr.zero[1] = pseudo6_hdr.zero[2] = 0;
        pseudo6_hdr.proto = IPPROTO_TCP;
        pseudo_hdr = &pseudo6_hdr;
        pseudo_hdr_len = sizeof(pseudo6_hdr);
    }

    if (pseudo_hdr_nbytes > [data length] - skip_bytes)
        return 0;

    partial_sum = in_cksum_partial(pseudo_hdr, pseudo_hdr_len, 0);
    partial_sum = in_cksum_partial(hdr, pseudo_hdr_nbytes, partial_sum);
    calced_sum = in_cksum_fold(partial_sum);
    hdr->th_sum = saved_sum;

    return calced_sum;
}

- (uint32_t)seqNo
{
    return seq_no;
}

- (uint32_t)ackNo
{
    return ack_no;
}

- (unsigned int)srcPort
{
    return sport;
}

- (unsigned int)dstPort
{
    return dport;
}

- (uint8_t)flags
{
    return flags;
}

- (BOOL)eceFlag
{
    return (flags & TH_ECE) != 0;
}

- (BOOL)cwrFlag
{
    return (flags & TH_CWR) != 0;
}

- (BOOL)urgFlag
{
    return (flags & TH_URG) != 0;
}

- (BOOL)ackFlag
{
    return (flags & TH_ACK) != 0;
}

- (BOOL)pushFlag
{
    return (flags & TH_PUSH) != 0;
}

- (BOOL)rstFlag
{
    return (flags & TH_RST) != 0;
}

- (BOOL)synFlag
{
    return (flags & TH_SYN) != 0;
}

- (BOOL)finFlag
{
    return (flags & TH_FIN) != 0;
}

/* payload size */
- (uint32_t)size
{
    NSArray* decoders;
    unsigned int i;
    size_t front;
    size_t iplen;

    if (size != UINT32_MAX)
        return size;

    if ((decoders = [parent decoders]) == nil)
        return 0;

    front = 0;
    iplen = 0;
    size = 0;

    for (i = 0; i < [decoders count]; ++i)
    {
        /* we need to find the ip length so that we do not incorrectly count trailers from other protocols */
        if (iplen == 0 &&
            [[decoders objectAtIndex:i] isMemberOfClass:[IPV4Decode class]])
        {
            iplen = [[decoders objectAtIndex:i] length];

            /* check for bogus IP length */
            if (iplen <= [[decoders objectAtIndex:i] frontSize] ||
                iplen > [parent captureLength] - front)
                return 0;

            /* reset front, we no longer care about what came before the IP header */
            front = [[decoders objectAtIndex:i] frontSize];
            continue;
        }
        else
            front += [[decoders objectAtIndex:i] frontSize];

        if (iplen == 0)
            continue;

        if ([decoders objectAtIndex:i] == self)
        {
            size = (uint32_t)(iplen - front);
            return size;
        }
    }

    return 0;
}

- (NSData*)payload
{
    NSArray* decoders;
    unsigned int i;
    size_t front;
    size_t htotal;
    size_t iplen;

    if ((decoders = [parent decoders]) == nil)
        return nil;

    front = 0;
    htotal = 0;
    iplen = 0;

    for (i = 0; i < [decoders count]; ++i)
    {
        htotal += [[decoders objectAtIndex:i] frontSize];

        if (iplen == 0 &&
            [[decoders objectAtIndex:i] isMemberOfClass:[IPV4Decode class]])
        {
            iplen = [[decoders objectAtIndex:i] length];

            /* check for bogus IP length */
            if (iplen <= [[decoders objectAtIndex:i] frontSize] ||
                iplen > [parent captureLength] - front)
                return nil;

            /* reset front, we no longer care about what came before the IP header */
            front = [[decoders objectAtIndex:i] frontSize];
            continue;
        }
        else
            front += [[decoders objectAtIndex:i] frontSize];

        if (iplen == 0)
            continue;

        if ([decoders objectAtIndex:i] == self)
        {
            if (iplen == front) /* no payload present */
                return nil;
            return [NSData
                dataWithBytesNoCopy:((uint8_t*)[[parent packetData] bytes] +
                                     htotal)
                             length:iplen - front
                       freeWhenDone:NO];
        }
    }

    return nil;
}

- (IPV4Decode*)ip
{
    return [parent decoderForClass:[IPV4Decode class]];
}

- (id<PPDecoderParent>)parent
{
    return parent;
}

- (NSDate*)date
{
    return [parent date];
}

- (BOOL)isInOrder
{
    return inOrder;
}

- (void)setInOrder:(BOOL)flag
{
    inOrder = flag;
}

- (void)setBackPointer:(void*)ptr
{
    back_ptr = ptr;
}

- (void*)backPointer
{
    return back_ptr;
}

- (BOOL)isEqualToSegment:(TCPDecode*)segment
{
    return (self == segment ||
            (sport == [segment srcPort] && dport == [segment dstPort] &&
             seq_no == [segment seqNo] && ack_no == [segment ackNo] &&
             flags == [segment flags] && [self size] == [segment size]))
               ? YES
               : NO;
}

- (NSString*)description
{
    return [NSString stringWithFormat:@"[TCP %@: S: %u, A: %u, %uB]",
                                      [self flagsStr],
                                      seq_no,
                                      ack_no,
                                      [self size]];
}

/* ColumnIdentifier protocol methods */

+ (NSArray*)columnIdentifiers
{
    ColumnIdentifier* colIdent;
    NSMutableArray* ret;
    unsigned int i;

    ret = [[NSMutableArray alloc]
        initWithCapacity:sizeof(names) / sizeof(names[0])];

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    {
        colIdent = [[ColumnIdentifier alloc] initWithDecoder:[self class]
                                                       index:i
                                                    longName:names[i][0]
                                                   shortName:names[i][1]];
        [ret addObject:colIdent];
        [colIdent release];
    }

    return [ret autorelease];
}

- (NSString*)columnStringForIndex:(unsigned int)fieldIndex
{
    switch (fieldIndex)
    {
    case 0:
        return [NSString stringWithFormat:@"%u", sport];
    case 1:
        return [NSString stringWithFormat:@"%u", dport];
    case 2:
        return [NSString stringWithFormat:@"%u", seq_no];
    case 3:
        return [NSString stringWithFormat:@"%u", ack_no];
    case 4:
        return [NSString stringWithFormat:@"%u (%u B)", hlen, hlen * 4];
    case 5:
        return [NSString stringWithFormat:@"0x%.2x", flags];
    case 6:
        return [NSString stringWithFormat:@"%u B", win_sz];
    case 7:
        return [NSString stringWithFormat:@"0x%.4x", sum];
    case 8:
        return [NSString stringWithFormat:@"%u", urg_ptr];
    case 9:
        return [NSString stringWithFormat:@"%u", [self size]];
    case 10:
        return (inOrder ? @"Yes" : @"No");
    case 11:
        return [self srcPortName];
    case 12:
        return [self dstPortName];
    case 13:
        return [self flagsStr];
    }

    return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
    switch (fieldIndex)
    {
    case 0:
        return val_compare(sport, ((TCPDecode*)obj)->sport);
    case 1:
        return val_compare(dport, ((TCPDecode*)obj)->dport);
    case 2:
        return val_compare(seq_no, ((TCPDecode*)obj)->seq_no);
    case 3:
        return val_compare(ack_no, ((TCPDecode*)obj)->ack_no);
    case 4:
        return val_compare(hlen, ((TCPDecode*)obj)->hlen);
    case 5:
        return val_compare(flags, ((TCPDecode*)obj)->flags);
    case 6:
        return val_compare(win_sz, ((TCPDecode*)obj)->win_sz);
    case 7:
        return val_compare(sum, ((TCPDecode*)obj)->sum);
    case 8:
        return val_compare(urg_ptr, ((TCPDecode*)obj)->urg_ptr);
    case 9:
        return val_compare([self size], [obj size]);
    case 10:
        return val_compare(inOrder, ((TCPDecode*)obj)->inOrder);
    case 11:
        return [[[PortCache sharedPortCache] serviceWithTCPPort:dport]
            compare:[[PortCache sharedPortCache]
                        serviceWithTCPPort:((TCPDecode*)obj)->dport]];
    case 12:
        return [[[PortCache sharedPortCache] serviceWithTCPPort:sport]
            compare:[[PortCache sharedPortCache]
                        serviceWithTCPPort:((TCPDecode*)obj)->sport]];
    case 13:
        return [[self flagsStr] compare:[obj flagsStr]];
    }

    return NSOrderedSame;
}

/* OutlineView protocol methods */

- (BOOL)expandable
{
    return YES;
}

- (size_t)numberOfChildren
{
    return 11; // XXX plus options
}

- (id)childAtIndex:(int)fieldIndex
{
    OutlineViewItem* ret;
    NSString* str;

    ret = [[OutlineViewItem alloc] init];
    [ret addObject:names[fieldIndex][0]];

    switch (fieldIndex)
    {
    case 0:
        str = [[NSString alloc] initWithFormat:@"%u", sport];
        [ret addObject:str];
        [str release];
        if ((str = [[PortCache sharedPortCache] serviceWithTCPPort:sport]) ==
            nil)
            str = @"Lookup failed";
        [ret addChildWithObjects:names[11][0], str, nil];
        break;
        /* NOTREACHED */

    case 1:
        str = [[NSString alloc] initWithFormat:@"%u", dport];
        [ret addObject:str];
        [str release];
        if ((str = [[PortCache sharedPortCache] serviceWithTCPPort:dport]) ==
            nil)
            str = @"Lookup failed";
        [ret addChildWithObjects:names[12][0], str, nil];
        break;
        /* NOTREACHED */

    case 2:
        str = [[NSString alloc] initWithFormat:@"%u", seq_no];
        [ret addObject:str];
        [str release];
        break;
        /* NOTREACHED */

    case 3:
        str = [[NSString alloc] initWithFormat:@"%u", ack_no];
        [ret addObject:str];
        [str release];
        break;
        /* NOTREACHED */

    case 4:
        str =
            [[NSString alloc] initWithFormat:@"%u (%u Bytes)", hlen, hlen * 4];
        [ret addObject:str];
        [str release];
        break;
        /* NOTREACHED */

    case 5:
        str = [[NSString alloc]
            initWithFormat:@"0x%.2x (%@)", flags, [self flagsStr]];
        [ret addObject:str];
        [str release];
        [ret addChildWithObjects:[NSString
                                     stringWithFormat:@"ECN-Echo (ECE): %s",
                                                      (flags & TH_ECE)
                                                          ? "set"
                                                          : "unset"],
                                 [NSString
                                     stringWithFormat:@"%u... ....",
                                                      (flags & TH_ECE) != 0],
                                 nil];
        [ret addChildWithObjects:
                 [NSString
                     stringWithFormat:@"Congestion window reduction (CWR): %s",
                                      (flags & TH_CWR) ? "set" : "unset"],
                 [NSString
                     stringWithFormat:@".%u.. ....", (flags & TH_CWR) != 0],
                 nil];
        [ret addChildWithObjects:
                 [NSString stringWithFormat:@"Urgent pointer (URG): %s",
                                            (flags & TH_URG) ? "set" : "unset"],
                 [NSString
                     stringWithFormat:@"..%u. ....", (flags & TH_URG) != 0],
                 nil];
        [ret addChildWithObjects:
                 [NSString stringWithFormat:@"Acknowledgement number (ACK): %s",
                                            (flags & TH_ACK) ? "set" : "unset"],
                 [NSString
                     stringWithFormat:@"...%u ....", (flags & TH_ACK) != 0],
                 nil];
        [ret addChildWithObjects:[NSString stringWithFormat:@"Push (PSH): %s",
                                                            (flags & TH_PUSH)
                                                                ? "set"
                                                                : "unset"],
                                 [NSString
                                     stringWithFormat:@".... %u...",
                                                      (flags & TH_PUSH) != 0],
                                 nil];
        [ret addChildWithObjects:
                 [NSString stringWithFormat:@"Reset connection (RST): %s",
                                            (flags & TH_RST) ? "set" : "unset"],
                 [NSString
                     stringWithFormat:@".... .%u..", (flags & TH_RST) != 0],
                 nil];
        [ret addChildWithObjects:
                 [NSString
                     stringWithFormat:@"Synchronize sequence numbers (SYN): %s",
                                      (flags & TH_SYN) ? "set" : "unset"],
                 [NSString
                     stringWithFormat:@".... ..%u.", (flags & TH_SYN) != 0],
                 nil];
        [ret addChildWithObjects:[NSString
                                     stringWithFormat:@"End of data (FIN): %s",
                                                      (flags & TH_FIN)
                                                          ? "set"
                                                          : "unset"],
                                 [NSString
                                     stringWithFormat:@".... ...%u",
                                                      (flags & TH_FIN) != 0],
                                 nil];
        break;
        /* NOTREACHED */

    case 6:
        str = [[NSString alloc] initWithFormat:@"%u Bytes", win_sz];
        [ret addObject:str];
        [str release];
        break;
        /* NOTREACHED */

    case 7:
        if (sum == [self computedChecksum])
            str = [[NSString alloc] initWithFormat:@"0x%.4x (correct)", sum];
        else
            str = [[NSString alloc]
                initWithFormat:@"0x%.4x (incorrect, should be 0x%.4x)",
                               sum,
                               [self computedChecksum]];
        [ret addObject:str];
        [str release];
        break;
        /* NOTREACHED */

    case 8:
        str = [[NSString alloc] initWithFormat:@"%u", urg_ptr];
        [ret addObject:str];
        [str release];
        break;
        /* NOTREACHED */

    case 9:
        str = [[NSString alloc] initWithFormat:@"%u Bytes", [self size]];
        [ret addObject:str];
        [str release];
        break;
        /* NOTREACHED */

    case 10:
        str = inOrder ? @"Yes" : @"No";
        [ret addObject:str];
        break;
        /* NOTREACHED */

    default:
        [ret release];
        return nil;
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

- (void)encodeWithCoder:(NSCoder*)coder
{
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&sport];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&dport];
    [coder encodeValueOfObjCType:@encode(uint32_t) at:&seq_no];
    [coder encodeValueOfObjCType:@encode(uint32_t) at:&ack_no];
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&hlen];
    [coder encodeValueOfObjCType:@encode(uint8_t) at:&flags];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&win_sz];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&sum];
    [coder encodeValueOfObjCType:@encode(uint16_t) at:&urg_ptr];
}

- (id)initWithCoder:(NSCoder*)coder
{
    if ((self = [super init]) != nil)
    {
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&sport];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&dport];
        [coder decodeValueOfObjCType:@encode(uint32_t) at:&seq_no];
        [coder decodeValueOfObjCType:@encode(uint32_t) at:&ack_no];
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&hlen];
        [coder decodeValueOfObjCType:@encode(uint8_t) at:&flags];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&win_sz];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&sum];
        [coder decodeValueOfObjCType:@encode(uint16_t) at:&urg_ptr];
        size = UINT32_MAX;
        inOrder = YES;
        calced_sum = 0;
        back_ptr = NULL;
    }
    return self;
}

/* speedups for stream_insert function in PPTCPStreamController */

inline BOOL tcpdecode_rstFlag(TCPDecode* segment)
{
    return (segment->flags & TH_RST) != 0;
}

inline BOOL tcpdecode_ackFlag(TCPDecode* segment)
{
    return (segment->flags & TH_ACK) != 0;
}

inline BOOL tcpdecode_synFlag(TCPDecode* segment)
{
    return (segment->flags & TH_SYN) != 0;
}

inline BOOL tcpdecode_finFlag(TCPDecode* segment)
{
    return (segment->flags & TH_FIN) != 0;
}

@end
