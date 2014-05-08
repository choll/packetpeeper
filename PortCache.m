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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#import <Foundation/NSString.h>
#import <Foundation/NSNull.h>
#import <Foundation/NSBundle.h>
#include "PortCache.h"

#define PORTCACHE_TCP_DATFILE_PATH		[[[NSBundle mainBundle] pathForResource:@"port-numbers-tcp" ofType:@"port"] UTF8String]
#define PORTCACHE_TCP_DATFILE_MAGIC		0x1A0D

#define PORTCACHE_UDP_DATFILE_PATH		[[[NSBundle mainBundle] pathForResource:@"port-numbers-udp" ofType:@"port"] UTF8String]
#define PORTCACHE_UDP_DATFILE_MAGIC		0x1B0D

#define PORTCACHE_FLAG_HASEQUIVALENT	0x1

#define PORTCACHE_RECORD_NULL			1
#define PORTCACHE_RECORD_FOUND			0

static int read_service(int fd, uint16_t port, unsigned int recsz, char *outbuf, size_t outbuf_sz, uint8_t *outflags);

static int port_comp(const void *key_a, const void *key_b);

static unsigned int port_hash(const void *key);

static PortCache *_sharedPortCache = nil;

#define DATFILE_HDR_SZ		4

struct datfile_hdr {
	uint16_t magic;
	uint16_t recsz;
};

#define DATFILE_RECHDR_SZ	3

struct datfile_rec {
	uint16_t len;
	uint8_t flags;
};

@interface PPServicePair : NSObject
{
	id tcp;
	id udp;
}

- (id)tcpService;
- (id)udpService;
- (void)setTCPService:(id)service;
- (void)setUDPService:(id)service;

@end

@implementation PPServicePair

- (id)init
{
	if((self = [super init]) != nil) {
		tcp = nil;
		udp = nil;
	}

	return self;
}

- (id)tcpService
{
	return tcp;
}

-(id)udpService
{
	return udp;
}

- (void)setTCPService:(id)service
{
	[service retain];
	[tcp release];
	tcp = service;
}

- (void)setUDPService:(id)service
{
	[service retain];
	[udp release];
	udp = service;
}

- (void)dealloc
{
	[tcp release];
	[udp release];
	[super dealloc];
}

@end

@implementation PortCache

+ (PortCache *)sharedPortCache
{
	if(_sharedPortCache == nil)
		_sharedPortCache = [[PortCache alloc] init];

	return _sharedPortCache;
}

+ (void)releaseSharedPortCache
{
	[_sharedPortCache release];
	_sharedPortCache = nil;
}

- (id)init
{
	struct datfile_hdr hdr;

	if((self = [super initWithKeySize:sizeof(uint16_t) hashSlots:PC_HASHTABLE_SZ hashFunction:port_hash comparisonFunction:port_comp]) != nil) {
		tcp_fd = -1;
		udp_fd = -1;
		service_description = NULL;

		if((tcp_fd = open(PORTCACHE_TCP_DATFILE_PATH, O_RDONLY, 0)) == -1)
			goto err;

		if(read(tcp_fd, &hdr, sizeof(hdr)) != sizeof(hdr))
			goto err;

		hdr.recsz = ntohs(hdr.recsz);

		if(hdr.magic != PORTCACHE_TCP_DATFILE_MAGIC || hdr.recsz < DATFILE_RECHDR_SZ)
			goto err;
            
		tcp_recsz = hdr.recsz;

		if((udp_fd = open(PORTCACHE_UDP_DATFILE_PATH, O_RDONLY, 0)) == -1)
			goto err;

		if(read(udp_fd, &hdr, sizeof(hdr)) != sizeof(hdr))
			goto err;

		hdr.recsz = ntohs(hdr.recsz);

		if(hdr.magic != PORTCACHE_UDP_DATFILE_MAGIC || hdr.recsz < DATFILE_RECHDR_SZ)
			goto err;
            
		udp_recsz = hdr.recsz;

		service_description_sz = MAX(udp_recsz, tcp_recsz) - 2;

		if((service_description = malloc(service_description_sz)) == NULL)
			goto err;

	}
	return self;

	err:
		[self dealloc];
		return nil;
}

- (NSString *)serviceWithTCPPort:(uint16_t)port
{
	return [self serviceWithPort:port protocol:PC_PROTO_TCP];
}

- (NSString *)serviceWithUDPPort:(uint16_t)port
{
	return [self serviceWithPort:port protocol:PC_PROTO_UDP];
}

- (NSString *)readServiceWithPort:(uint16_t)port protocol:(int)proto isUnified:(BOOL *)unified
{
	int fd, ret;
	uint16_t recsz;
	uint8_t flags;
	id str;

	if(proto == PC_PROTO_TCP) {
		fd = tcp_fd;
		recsz = tcp_recsz;
	} else {
		fd = udp_fd;
		recsz = udp_recsz;
	}

	flags = 0;

	ret = read_service(fd, port, recsz, service_description, service_description_sz, &flags);

	if(ret == PORTCACHE_RECORD_NULL)
		str = [NSNull null];
	else if(ret == PORTCACHE_RECORD_FOUND)
		str = [NSString stringWithUTF8String:service_description];
	else
		return nil;

	if(unified != NULL)
		*unified = (flags & PORTCACHE_FLAG_HASEQUIVALENT) ? YES : NO;

	return str;
}

- (NSString *)serviceWithPort:(uint16_t)port protocol:(int)proto
{
	PPServicePair *result;
	BOOL unified;
	id str;

	result = [super objectForKey:&port];

	if(result == nil ||
	  (proto == PC_PROTO_TCP && [result tcpService] == nil) || 
	  (proto == PC_PROTO_UDP && [result udpService] == nil)) {
		/* str will be NSNull or the service name */
		if((str = [self readServiceWithPort:port protocol:proto isUnified:&unified]) == nil)
			return nil;

		/* only allocate/insert if needed */
		if(result == nil) {
			if((result = [[PPServicePair alloc] init]) == nil)
				return nil;

			[super insertObject:result forKey:&port];
		}

		if(proto == PC_PROTO_UDP) {
			[result setUDPService:str];
			if(unified)
				[result setTCPService:str];
		} else {
			[result setTCPService:str];
			if(unified)
				[result setUDPService:str];
		}
	}

	if(proto == PC_PROTO_UDP)
		str = [result udpService];
	else
		str = [result tcpService];

	return (str == [NSNull null]) ? nil : str;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
	[super encodeWithCoder:coder];
}

- (id)initWithCoder:(NSCoder *)coder
{
	[super setHashFunction:port_hash];
	[super setComparisonFunction:port_comp];

	return [super initWithCoder:coder];
}

- (void)dealloc
{
	if(tcp_fd != -1)
		close(tcp_fd);
	if(udp_fd != -1)
		close(tcp_fd);
	if(service_description != NULL)
		free(service_description);

	[super dealloc];
}

@end

static int read_service(int fd, uint16_t port, unsigned int recsz, char *outbuf, size_t outbuf_sz, uint8_t *outflags)
{
	struct datfile_rec entry;

	if(port < 1)
		return -1;

	if(pread(fd, &entry, sizeof(entry), 4 + ((port - 1) * recsz)) != sizeof(entry))
		return -1;

	entry.len = ntohs(entry.len);

	if(entry.len == 0)
		return PORTCACHE_RECORD_NULL;

	entry.len = MIN(entry.len, outbuf_sz - 1);

	if(pread(fd, outbuf, entry.len, 4 + ((port - 1) * recsz) + 3) != entry.len)
		return -1;

	if(outflags != NULL)
		*outflags = entry.flags;

	outbuf[entry.len] = '\0';

	return PORTCACHE_RECORD_FOUND;
}

static int port_comp(const void *key_a, const void *key_b)
{
	return (*(uint16_t *)key_a - *(uint16_t *)key_b);
}

static unsigned int port_hash(const void *key)
{
	return (*(uint16_t *)key & PC_HASHMASK);
}
