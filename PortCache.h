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

#ifndef _PORTCACHE_H_
#define _PORTCACHE_H_

#include "Cache.h"
#include <pthread.h>
#include <stdint.h>

#define PC_HASHMASK     (PC_HASHTABLE_SZ - 1)
#define PC_HASHTABLE_SZ 256
#define PC_PROTO_TCP    0
#define PC_PROTO_UDP    1

@interface PortCache : Cache
{
    char* service_description;
    size_t service_description_sz;
    unsigned int tcp_recsz;
    unsigned int udp_recsz;
    int tcp_fd;
    int udp_fd;
}

+ (PortCache*)sharedPortCache;
+ (void)releaseSharedPortCache;
- (NSString*)serviceWithTCPPort:(uint16_t)port;
- (NSString*)serviceWithUDPPort:(uint16_t)port;
- (NSString*)readServiceWithPort:(uint16_t)port
                        protocol:(int)proto
                       isUnified:(BOOL*)unified;
- (NSString*)serviceWithPort:(uint16_t)port protocol:(int)proto;

@end

#endif /* _PORTCACHE_H_ */
