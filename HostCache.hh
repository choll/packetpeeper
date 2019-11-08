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

#ifndef PACKETPEEPER_HOSTCACHE_HPP
#define PACKETPEEPER_HOSTCACHE_HPP

#include <Foundation/NSObject.h>
#include <netinet/in.h>

#define PPHostCacheHostNameLookupCompleteNotification @"PPHostCache.LComp"

#define HOSTCACHE_SUCCESS 1 /* successful lookup */
#define HOSTCACHE_NONAME  2 /* lookup failed */
#define HOSTCACHE_INPROG  3 /* lookup in progress */
#define HOSTCACHE_ERROR   4 /* error occured */

@interface HostCache : NSObject
{
}

+ (HostCache*)sharedHostCache;
+ (void)releaseSharedHostCache;
- (void)lookupComplete:(id)sender;
- (void)flush;
- (NSString*)hostWithAddressASync:(const struct in_addr*)addr
                       returnCode:(int*)code;
- (NSString*)hostWithIp6AddressASync:(const struct in6_addr*)addr
                          returnCode:(int*)code;

@end

#endif
