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
#include <sys/uio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#import <Foundation/NSString.h>
#import <Foundation/NSNull.h>
#import <Foundation/NSBundle.h>
#include "OUICache.h"

#define OUICACHE_DATFILE_PATH		[[[NSBundle mainBundle] pathForResource:@"ethernet-manufacturers" ofType:@"oui"] UTF8String]
#define OUICACHE_DATFILE_MAGIC		0x1C0D

#define OUICACHE_RECORD_NULL		1
#define OUICACHE_RECORD_FOUND		0

static int read_oui(int fd, uint32_t oui, unsigned int recsz, unsigned int nrecs, char *outbuf, size_t outbuf_sz);

static int oui_comp(const void *key_a, const void *key_b);

static unsigned int oui_hash(const void *key);

static OUICache *_sharedOUICache = nil;

#define DATFILE_HDR_SZ		6

struct datfile_hdr {
	uint16_t magic;
	uint16_t recsz;
	uint16_t nrecs;
};

#define DATFILE_RECHDR_SZ	6

struct datfile_rec {
	uint32_t oui;
	uint16_t len;
};

@implementation OUICache

+ (OUICache *)sharedOUICache
{
	if(_sharedOUICache == nil)
		_sharedOUICache = [[OUICache alloc] init];

	return _sharedOUICache;
}

+ (void)releaseSharedOUICache
{
	[_sharedOUICache release];
	_sharedOUICache = nil;
}

- (id)init
{
	struct datfile_hdr hdr;

	if((self = [super initWithKeySize:sizeof(uint32_t) hashSlots:OC_HASHTABLE_SZ hashFunction:oui_hash comparisonFunction:oui_comp]) != nil) {
		fd = -1;
		manufacturer = NULL;

		if((fd = open(OUICACHE_DATFILE_PATH, O_RDONLY, 0)) == -1)
			goto err;

		if(read(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
			goto err;
        
		hdr.recsz = ntohs(hdr.recsz);
		hdr.nrecs = ntohs(hdr.nrecs);

		if(hdr.magic != OUICACHE_DATFILE_MAGIC || hdr.recsz < DATFILE_RECHDR_SZ || hdr.nrecs < 1)
			goto err;
        
		recsz = hdr.recsz;
		nrecs = hdr.nrecs;

		manufacturer_sz = recsz - 4;

		if((manufacturer = malloc(manufacturer_sz)) == NULL)
			goto err;
	}
	return self;
    
	err:
		[self dealloc];
		return nil;
}

- (NSString *)readManufacturerForEthernetAddress:(void *)addr
{
	int ret;
	uint32_t oui;
	id str;

    oui = ntohl(*(uint32_t *)addr) >> 8;
    
	ret = read_oui(fd, oui, recsz, nrecs, manufacturer, manufacturer_sz);

	if(ret == OUICACHE_RECORD_NULL)
		str = [NSNull null];
	else if(ret == OUICACHE_RECORD_FOUND)
		str = [NSString stringWithUTF8String:manufacturer];
	else
		return nil;

	return str;
}

- (NSString *)manufacturerForEthernetAddress:(void *)addr
{
	id str;
	uint32_t oui;

    oui = ntohl(*(uint32_t *)addr) >> 8;
	str = [super objectForKey:&oui];

	if(str == nil) {
		/* str will be NSNull or the manufacturer name */
		if((str = [self readManufacturerForEthernetAddress:addr]) == nil)
			return nil;

		[super insertObject:str forKey:&oui];
	}

	return (str == [NSNull null]) ? nil : str;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
	[super encodeWithCoder:coder];
}

- (id)initWithCoder:(NSCoder *)coder
{
	[super setHashFunction:oui_hash];
	[super setComparisonFunction:oui_comp];

	return [super initWithCoder:coder];
}

- (void)dealloc
{
	if(fd != -1)
		close(fd);
	if(manufacturer != NULL)
		free(manufacturer);

	[super dealloc];
}

@end

static int read_oui(int fd, uint32_t oui, unsigned int recsz, unsigned int nrecs, char *outbuf, size_t outbuf_sz)
{
	unsigned int mid, left, right;
	off_t offset;
	struct datfile_rec entry;

	left = 0;
	right = nrecs;

	do {
		if(right < left)
			return OUICACHE_RECORD_NULL;

		mid = (left + right) / 2;

		offset = DATFILE_HDR_SZ + (recsz * mid);

		if(pread(fd, &entry, sizeof(entry), offset) != sizeof(entry))
			return -1;

        entry.oui = ntohl(entry.oui);
        
		if(oui > entry.oui)
			left = mid + 1;

		if(oui < entry.oui)
			right = mid - 1;

	} while(oui != entry.oui);

	entry.len = MIN(ntohs(entry.len), outbuf_sz - 1);

	if(pread(fd, outbuf, entry.len, offset + DATFILE_RECHDR_SZ) != entry.len)
		return -1;

	outbuf[entry.len] = '\0';

	return OUICACHE_RECORD_FOUND;
}

static int oui_comp(const void *key_a, const void *key_b)
{
	return (*(uint32_t *)key_a - *(uint32_t *)key_b);
}

static unsigned int oui_hash(const void *key)
{
	return (*(uint32_t *)key & OC_HASHMASK);
}
