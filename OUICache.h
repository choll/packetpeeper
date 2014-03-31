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

#ifndef _OUICACHE_H_
#define _OUICACHE_H_

#include "Cache.h"

#define OC_HASHMASK			(OC_HASHTABLE_SZ - 1)
#define OC_HASHTABLE_SZ		256

@interface OUICache : Cache <NSCoding>
{
	char *manufacturer;
	size_t manufacturer_sz;
	int fd;
	unsigned int recsz;
	unsigned int nrecs;
}

+ (OUICache *)sharedOUICache;
+ (void)releaseSharedOUICache;
- (NSString *)readManufacturerForEthernetAddress:(void *)addr;
- (NSString *)manufacturerForEthernetAddress:(void *)addr;

@end

#endif /* _OUICACHE_H_ */
