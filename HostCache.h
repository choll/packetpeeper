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

#ifndef _HOSTCACHE_H_
#define _HOSTCACHE_H_

#include <netinet/in.h>
#include <pthread.h>
#include "Cache.h"

#define PPHostCacheHostNameLookupCompleteNotification	@"PPHostCache.LComp"

#define HOSTCACHE_SUCCESS	1	/* successful lookup */
#define HOSTCACHE_NONAME	2	/* lookup failed */
#define HOSTCACHE_INPROG	3	/* lookup in progress */
#define HOSTCACHE_ERROR		4	/* error occured */

/* note that mask and table size must match up,
   i.e the mask must extract N bits, where
   2^N = table size. */
#define HC_HASHMASK			(HC_HASHTABLE_SZ - 1)
#define HC_HASHTABLE_SZ		256

struct thread_args;

@interface HostCache : Cache <NSCoding>
{
	struct thread_args *thread_list;
	pthread_mutex_t mutex;
	pthread_attr_t thread_attr;
}

+ (HostCache *)sharedHostCache;
+ (void)releaseSharedHostCache;
- (void)lookupComplete:(id)sender;
- (NSString *)hostWithAddress:(struct in_addr *)addr;
- (NSString *)hostWithAddressASync:(struct in_addr *)addr returnCode:(int *)code;

@end

#endif /* _HOSTCACHE_H_ */
