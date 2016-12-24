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

#include "PPRVIDecode.h"
#include "Packet.h"
#include "ColumnIdentifier.h"
#include "strfuncs.h"
#include "pkt_compare.h"
#include "dlt_lookup.h"

#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSArchiver.h>

#include <sys/param.h> // MAXCOMLEN
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>

#define PACKETPEEPER_PKTAP_IFXNAMESIZE (IF_NAMESIZE + 8)

// This is copied from xnu/bsd/net/pktap.h. Doesn't seem to be in /usr/include.
struct pp_pktap_header {
    uint32_t pth_length;                                /* length of this header */
    uint32_t pth_type_next;                             /* type of data following */
    uint32_t pth_dlt;                                   /* DLT of packet */
    char pth_ifname[PACKETPEEPER_PKTAP_IFXNAMESIZE];    /* interface name */
    uint32_t pth_flags;                                 /* flags */
    uint32_t pth_protocol_family;
    uint32_t pth_frame_pre_length;
    uint32_t pth_frame_post_length;
    pid_t pth_pid;                                      /* process ID */
    char pth_comm[MAXCOMLEN+1];                         /* process command name */
    uint32_t pth_svc;                                   /* service class */
    uint16_t pth_iftype;
    uint16_t pth_ifunit;
    pid_t pth_epid;                                     /* effective process ID */
    char pth_ecomm[MAXCOMLEN+1];                        /* effective command name */
} __attribute__((__packed__));

static NSString *names[][2] =
    {{@"Length", @"RVI Len"},
    {@"Next header", @"RVI Next Hdr"},
    {@"DLT", @"RVI DLT"},
    {@"Interface name", @"RVI If. Name"},
    {@"Flags", @"RVI Flags"},
    {@"Protocol Family", @"RVI Proto. Fam."},
    {@"Frame Pre-Length", @"RVI Pre-Len"},
    {@"Frame Post-Length", @"RVI Post-Len"},
    {@"Process ID", @"RVI PID"},
    {@"Command name", @"RVI Cmd Name"},
    {@"Service class", @"RVI Svc Cls"},
    {@"Interface type", @"RVI If. Type"},
    {@"Interface unit", @"RVI If. Unit"},
    {@"Effective process ID", @"RVI EPID"},
    {@"Effective command name", @"RVI E.Cmd Name"}};

@implementation PPRVIDecode

- (id)initWithData:(NSData*)data parent:(id <PPDecoderParent>)parent
{
    if(
        data == nil ||
        [data length] < sizeof(struct pp_pktap_header) ||
        (self = [super init]) == nil)
    {
        return nil;
    }

    m_hdr = (struct pp_pktap_header*)[data bytes];
    m_parent = parent;

    return self;
}

- (void)setParent:(id <PPDecoderParent>)parent
{
    m_parent = parent;
    m_hdr =
        (struct pp_pktap_header*)((char*)[[m_parent packetData] bytes] +
            [m_parent byteOffsetForDecoder:self]);
}

- (size_t)frontSize
{
    return m_hdr->pth_length;
}

- (size_t)rearSize
{
	return 0;
}

- (Class)nextLayer
{
    return dlt_lookup(m_hdr->pth_dlt);
}

- (uint32_t)dlt
{
    return m_hdr->pth_dlt;
}

+ (NSString *)shortName
{
    return @"RVI";
}

+ (NSString*)longName
{
    return @"Remote Virtual Interface";
}

- (NSString*)info
{
    return [NSString stringWithFormat:@"RVI"];
}

- (stacklev)level
{
    return SL_DATALINK;
}

/* ColumnIdentifier protocol methods */

+ (NSArray*)columnIdentifiers
{
    ColumnIdentifier *colIdent;
    NSMutableArray* ret;
    unsigned int i;

    ret = [[NSMutableArray alloc] initWithCapacity:sizeof(names) / sizeof(names[0])];

    for(i = 0; i < sizeof(names) / sizeof(names[0]) ; ++i) {
        colIdent = [[ColumnIdentifier alloc] initWithDecoder:[self class] index:i longName:names[i][0] shortName:names[i][1]];
        [ret addObject:colIdent];
        [colIdent release];
    }

    return [ret autorelease];
}

- (NSString*)columnStringForIndex:(unsigned int)fieldIndex
{
    switch(fieldIndex) {
        case 0:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_length];
        case 1:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_type_next];
        case 2:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_dlt];
        case 3:
            return [NSString stringWithFormat:@"%s", m_hdr->pth_ifname];
        case 4:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_flags];
        case 5:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_protocol_family];
        case 6:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_frame_pre_length];
        case 7:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_frame_post_length];
        case 8:
            return [NSString stringWithFormat:@"%ld", (long)m_hdr->pth_pid];
        case 9:
            return [NSString stringWithFormat:@"%s", m_hdr->pth_comm];
        case 10:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_svc];
        case 11:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_iftype];
        case 12:
            return [NSString stringWithFormat:@"%u", m_hdr->pth_ifunit];
        case 13:
            return [NSString stringWithFormat:@"%ld", (long)m_hdr->pth_epid];
        case 14:
            return [NSString stringWithFormat:@"%s", m_hdr->pth_ecomm];
    }
    return nil;
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
    const struct pp_pktap_header* other = ((PPRVIDecode *)obj)->m_hdr;

    switch(fieldIndex) {
        case 0:
            return val_compare(m_hdr->pth_length, other->pth_length);
        case 1:
            return val_compare(m_hdr->pth_type_next, other->pth_type_next);
        case 2:
            return val_compare(m_hdr->pth_dlt, other->pth_dlt);
        case 3:
            return strcmp(m_hdr->pth_ifname, other->pth_ifname);
        case 4:
            return val_compare(m_hdr->pth_flags, other->pth_flags);
        case 5:
            return val_compare(m_hdr->pth_protocol_family, other->pth_protocol_family);
        case 6:
            return val_compare(m_hdr->pth_frame_pre_length, other->pth_frame_pre_length);
        case 7:
            return val_compare(m_hdr->pth_frame_post_length, other->pth_frame_post_length);
        case 8:
            return val_compare(m_hdr->pth_pid, other->pth_pid);
        case 9:
            return strcmp(m_hdr->pth_comm, other->pth_comm);
        case 10:
            return val_compare(m_hdr->pth_svc, other->pth_svc);
        case 11:
            return val_compare(m_hdr->pth_iftype, other->pth_iftype);
        case 12:
            return val_compare(m_hdr->pth_ifunit, other->pth_ifunit);
        case 13:
            return val_compare(m_hdr->pth_epid, other->pth_epid);
        case 14:
            return strcmp(m_hdr->pth_ecomm, other->pth_ecomm);
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
    return sizeof(names) / sizeof(names[0]);
}

- (id)childAtIndex:(int)fieldIndex
{
    OutlineViewItem* ret;
    NSString* str;

    ret = [[OutlineViewItem alloc] init];
    [ret addObject:names[fieldIndex][0]];

    switch(fieldIndex) {
        case 0:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_length];
            [ret addObject:str];
            [str release];
            break;
        case 1:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_type_next];
            [ret addObject:str];
            [str release];
            break;
        case 2:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_dlt];
            [ret addObject:str];
            [str release];
            break;
        case 3:
            str = [[NSString alloc] initWithFormat:@"%s", m_hdr->pth_ifname];
            [ret addObject:str];
            [str release];
            break;
        case 4:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_flags];
            [ret addObject:str];
            [str release];
            break;
        case 5:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_protocol_family];
            [ret addObject:str];
            [str release];
            break;
        case 6:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_frame_pre_length];
            [ret addObject:str];
            [str release];
            break;
        case 7:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_frame_post_length];
            [ret addObject:str];
            [str release];
            break;
        case 8:
            str = [[NSString alloc] initWithFormat:@"%ld", (long)m_hdr->pth_pid];
            [ret addObject:str];
            [str release];
            break;
        case 9:
            str = [[NSString alloc] initWithFormat:@"%s", m_hdr->pth_comm];
            [ret addObject:str];
            [str release];
            break;
        case 10:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_svc];
            [ret addObject:str];
            [str release];
            break;
        case 11:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_iftype];
            [ret addObject:str];
            [str release];
            break;
        case 12:
            str = [[NSString alloc] initWithFormat:@"%u", m_hdr->pth_ifunit];
            [ret addObject:str];
            [str release];
            break;
        case 13:
            str = [[NSString alloc] initWithFormat:@"%ld", (long)m_hdr->pth_epid];
            [ret addObject:str];
            [str release];
            break;
        case 14:
            str = [[NSString alloc] initWithFormat:@"%s", m_hdr->pth_ecomm];
            [ret addObject:str];
            [str release];
            break;
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
}

- (id)initWithCoder:(NSCoder*)coder
{
    if((self = [super init]) != nil) {
        m_parent = nil;
        m_hdr = NULL;
    }
    return self;
}

@end

