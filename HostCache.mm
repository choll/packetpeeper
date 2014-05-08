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

extern "C"
{
#include "getnameinfo.h"
}

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <utility>

#include <iostream>

#import <Foundation/NSThread.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArchiver.h>
#import <Foundation/NSNull.h>
#import <Foundation/NSNotification.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>

namespace
{
    HostCache *sharedHostCache = nil;

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
            return
                a.__u6_addr.__u6_addr32[0] < b.__u6_addr.__u6_addr32[0] &&
                a.__u6_addr.__u6_addr32[1] < b.__u6_addr.__u6_addr32[1] &&
                a.__u6_addr.__u6_addr32[2] < b.__u6_addr.__u6_addr32[2] &&
                a.__u6_addr.__u6_addr32[3] < b.__u6_addr.__u6_addr32[3];
        }
    };

    typedef std::unique_ptr<NSString, release_deleter<NSString>> nsstring_ptr;
    typedef std::pair<int, nsstring_ptr> cache_entry;
    typedef std::map<in_addr, cache_entry, ip_compare> ip4_map;
    typedef std::map<in_addr, cache_entry, ip_compare> ip6_map;
}

@implementation HostCache
{
    peep::async async_;
    ip4_map ip4_addrs_;
    ip4_map ip6_addrs_;
    std::mutex ip4_mutex_;
    std::mutex ip6_mutex_;
}

+ (HostCache *)sharedHostCache
{
    if(sharedHostCache == nil)
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
    [[NSNotificationCenter defaultCenter] postNotificationName:PPHostCacheHostNameLookupCompleteNotification object:self];
}

- (NSString *)hostWithAddressASync:(const in_addr *)addr returnCode:(int *)code
{
    try
    {
        std::lock_guard<std::mutex> lock(ip4_mutex_);

        auto result =
            ip4_addrs_.insert(
                std::make_pair(*addr, cache_entry(HOSTCACHE_ERROR, nsstring_ptr())));

        if (!result.second)
        {
            // element already present, so return immediately...
            cache_entry& entry(result.first->second);
            if (code != NULL)
                *code = entry.first;
            return entry.second.get();
        }

        // ...else the map now has ERROR (in case we throw) and a null
        // string, so tell the async_ pool to perform a lookup and give
        // it the cache_entry location to store the result in.

        const in_addr captured_addr = *addr;
        cache_entry& entry(result.first->second);
        auto f = [self, captured_addr, &entry] () {
            int ret;
            NSString* str;
            struct sockaddr_in sin;
            char host[NI_MAXHOST];

            sin.sin_len = sizeof(sin);
            sin.sin_family = AF_INET;
            sin.sin_addr = captured_addr;

            if ((ret = getnameinfo2((struct sockaddr *)&sin, sin.sin_len, host, sizeof(host), NULL, 0, NI_NAMEREQD)) != 0)
            {
                std::lock_guard<std::mutex> l_lock(self->ip4_mutex_);
                entry.first = (ret == EAI_NONAME) ? HOSTCACHE_NONAME : HOSTCACHE_ERROR;
            }
            else if((str = [[NSString alloc] initWithUTF8String:host]) != nil)
            {
                std::lock_guard<std::mutex> l_lock(self->ip4_mutex_);
                entry.first = HOSTCACHE_SUCCESS;
                entry.second = std::unique_ptr<NSString, release_deleter<NSString>>(str);
            }

            [self performSelectorOnMainThread:@selector(lookupComplete:) withObject:nil waitUntilDone:NO];
        };

        async_.enqueue(f);

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

- (NSString *)hostWithIp6AddressASync:(const in6_addr *)addr returnCode:(int *)code
{
    // TODO
    *code = HOSTCACHE_NONAME;
    return nil;
}

- (void)flush
{
    {
        std::lock_guard<std::mutex> lock(self->ip4_mutex_);
        self->ip4_addrs_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(self->ip6_mutex_);
        self->ip6_addrs_.clear();
    }
}

@end

