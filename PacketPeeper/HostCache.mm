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

#include "HostCache.hh"
#include "async.hpp"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <utility>

#include <iostream>

#import <Foundation/NSArchiver.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSNull.h>
#import <Foundation/NSString.h>
#import <Foundation/NSThread.h>

#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace
{
    HostCache* sharedHostCache = nil;

    template<typename T>
    struct release_deleter
    {
        void operator()(T* obj) const
        {
            [obj release];
        }
    };

    struct ip_compare
    {
        bool operator()(const in_addr& a, const in_addr& b) const
        {
            return a.s_addr < b.s_addr;
        }

        bool operator()(const in6_addr& a, const in6_addr& b) const
        {
            return a.__u6_addr.__u6_addr32[0] < b.__u6_addr.__u6_addr32[0] &&
                   a.__u6_addr.__u6_addr32[1] < b.__u6_addr.__u6_addr32[1] &&
                   a.__u6_addr.__u6_addr32[2] < b.__u6_addr.__u6_addr32[2] &&
                   a.__u6_addr.__u6_addr32[3] < b.__u6_addr.__u6_addr32[3];
        }
    };

    typedef std::unique_ptr<NSString, release_deleter<NSString>> nsstring_ptr;
    typedef std::pair<int, nsstring_ptr> cache_entry;
    typedef std::map<in_addr, cache_entry, ip_compare> ip4_map;
    typedef std::map<in6_addr, cache_entry, ip_compare> ip6_map;

    // Needed because sockaddr_in/sockaddr_in6 still have pre-C89 style prefixes
    // to their struct member names :l
    void sockaddr_helper(sockaddr_in& sin, int family, const in_addr& addr)
    {
        sin.sin_len = sizeof(sin);
        sin.sin_family = family;
        sin.sin_addr = addr;
    }

    void sockaddr_helper(sockaddr_in6& sin, int family, const in6_addr& addr)
    {
        sin.sin6_len = sizeof(sin);
        sin.sin6_family = family;
        sin.sin6_addr = addr;
    }

    template<typename SockAddrType, typename AddrType, typename MapType>
    NSString* lookup(
        HostCache* cache,
        peep::async& async,
        const AddrType& addr,
        int family,
        MapType& map,
        std::mutex& mutex,
        int* code)
    {
        try
        {
            std::lock_guard<std::mutex> lock(mutex);

            auto result = map.insert(std::make_pair(
                addr, cache_entry(HOSTCACHE_ERROR, nsstring_ptr())));

            cache_entry& entry(result.first->second);

            if (!result.second)
            {
                // element already present (including if a lookup is in progress),
                // so return immediately...
                if (code != NULL)
                    *code = entry.first;
                return entry.second.get();
            }

            // ...else the map now has ERROR (in case we throw) and a null
            // string, so schedule a lookup and give it the cache_entry
            // location to store the result in.

            auto f = [cache, addr, family, &entry, &mutex]() {
                int ret;
                NSString* str;
                SockAddrType sin; // sockaddr_in or sockaddr_in6
                char host[NI_MAXHOST];

                sockaddr_helper(sin, family, addr);

                if ((ret = ::getnameinfo(
                         reinterpret_cast<struct sockaddr*>(&sin),
                         sizeof(sin),
                         host,
                         sizeof(host),
                         NULL,
                         0,
                         NI_NAMEREQD)) != 0)
                {
                    std::lock_guard<std::mutex> lock2(mutex);
                    entry.first = (ret == EAI_NONAME) ? HOSTCACHE_NONAME
                                                      : HOSTCACHE_ERROR;
                }
                else if (
                    (str = [[NSString alloc] initWithUTF8String:host]) != nil)
                {
                    std::lock_guard<std::mutex> lock2(mutex);
                    entry.first = HOSTCACHE_SUCCESS;
                    entry.second =
                        std::unique_ptr<NSString, release_deleter<NSString>>(
                            str);
                }

                [cache performSelectorOnMainThread:@selector(lookupComplete:)
                                        withObject:nil
                                     waitUntilDone:NO];
            };

            async.enqueue(f);

            // Async call dispatched so safe to mark as in-progress now
            entry.first = HOSTCACHE_INPROG;

            if (code != NULL)
                *code = HOSTCACHE_INPROG;
        }
        catch (const std::exception& e)
        {
            if (code != NULL)
                *code = HOSTCACHE_ERROR;
        }

        return nil;
    }
}

@implementation HostCache
{
    peep::async async_;
    ip4_map ip4_addrs_;
    ip6_map ip6_addrs_;
    std::mutex ip4_mutex_;
    std::mutex ip6_mutex_;
}

+ (HostCache*)sharedHostCache
{
    if (sharedHostCache == nil)
        sharedHostCache = [[HostCache alloc] init];
    return sharedHostCache;
}

+ (void)releaseSharedHostCache
{
    [sharedHostCache release];
    sharedHostCache = nil;
}

- (id)init
{
    self = [super init];
    return self;
}

- (void)dealloc
{
    [super dealloc];
}

- (void)lookupComplete:(id)sender
{
    [[NSNotificationCenter defaultCenter]
        postNotificationName:PPHostCacheHostNameLookupCompleteNotification
                      object:self];
}

- (NSString*)hostWithAddressASync:(const in_addr*)addr returnCode:(int*)code
{
    return lookup<struct sockaddr_in>(
        self, async_, *addr, AF_INET, ip4_addrs_, ip4_mutex_, code);
}

- (NSString*)hostWithIp6AddressASync:(const in6_addr*)addr returnCode:(int*)code
{
    return lookup<struct sockaddr_in6>(
        self, async_, *addr, AF_INET6, ip6_addrs_, ip6_mutex_, code);
}

- (void)flush
{
    {
        std::lock_guard<std::mutex> lock(ip4_mutex_);
        ip4_addrs_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(ip6_mutex_);
        ip6_addrs_.clear();
    }
}

@end
