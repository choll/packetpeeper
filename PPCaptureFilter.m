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
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <pcap.h>
#include <inttypes.h>
#import <Foundation/NSObject.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArchiver.h>
#include "PPBPFProgram.h"

#include "PPCaptureFilter.h"

@implementation PPCaptureFilter

- (id)initWithTCPDumpFilter:(NSString *)filter name:(NSString *)name
{
	if((self = [super init]) != nil) {
		m_filter = [filter retain];
		m_name = [name retain];
		m_netmask = 0;
		m_compileError = nil;
	}
	return self;
}

- (id)initWithTCPDumpFilter:(NSString *)filter
{
	return [self initWithTCPDumpFilter:filter name:nil];
}

- (PPBPFProgram *)filterProgramForLinkType:(int)linkType
{
	PPBPFProgram *program;
	pcap_t *cap;
	struct bpf_program bpf_program;

	if((cap = pcap_open_dead(linkType, BPF_MAXBUFSIZE)) == NULL)
		return nil;

	if(pcap_compile(cap, &bpf_program, (char *)[m_filter UTF8String],  1,  m_netmask) == -1) {
		const char *err;

		if((err = pcap_geterr(cap)) != NULL)
			m_compileError = [[NSString alloc] initWithUTF8String:err];

		pcap_close(cap);
		return nil;
	}

	program = [[PPBPFProgram alloc] initWithProgram:&bpf_program];

	pcap_freecode(&bpf_program); /* pcap_close() probably does this for us, but the docs dont say so */
	pcap_close(cap);
	return [program autorelease];
}

- (NSString *)errorString
{
	return m_compileError;
}

- (NSString *)filterText
{
	return m_filter;
}

- (NSString *)name
{
	return m_name;
}

- (void)setName:(NSString *)name
{
	[name retain];
	[m_name release];
	m_name = name;
}

- (uint32_t)netmask
{
	return m_netmask;
}

- (void)setNetmask:(uint32_t)netmask
{
	m_netmask = netmask;
}

- (id)copyWithZone:(NSZone *)zone
{
	PPCaptureFilter *copy;
	NSString *filterCopy;
	NSString *nameCopy;

	filterCopy = nil;
	nameCopy = nil;

	if([self filterText] != nil)
		filterCopy = [[self filterText] copyWithZone:zone];
	if([self name] != nil)
		nameCopy = [[self name] copyWithZone:zone];

	copy = [[[self class] allocWithZone:zone] initWithTCPDumpFilter:filterCopy name:nameCopy];

	[filterCopy release];
	[nameCopy release];

	return copy;
}

- (NSString *)description
{
	return [NSString stringWithFormat:@"<PPCaptureFilter [%p]: name: '%@' filter: '%@' compileError: '%@'>", self, m_name, m_filter, m_compileError];
}

- (void)encodeWithCoder:(NSCoder *)encoder
{
	[encoder encodeObject:m_filter];
	[encoder encodeObject:m_name];
	[encoder encodeValueOfObjCType:@encode(uint32_t) at:&m_netmask];
}

- (id)initWithCoder:(NSCoder *)decoder
{
	if((self = [super init]) != nil) {
		m_filter = [[decoder decodeObject] retain];
		m_name = [[decoder decodeObject] retain];
		[decoder decodeValueOfObjCType:@encode(uint32_t) at:&m_netmask];
	}
	return self;
}

- (void)dealloc
{
	[m_filter release];
	[m_name release];
	[m_compileError release];
	[super dealloc];
}

@end
