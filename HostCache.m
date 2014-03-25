/*
 * Packet Peeper
 * Copyright 2006, 2007, Chris E. Holloway
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
#include <netdb.h>
#include <stdlib.h>
#import <Foundation/NSThread.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArchiver.h>
#import <Foundation/NSNull.h>
#import <Foundation/NSNotification.h>
#include "getnameinfo.h"
#include "HostCache.h"

struct thread_args {
	struct thread_args **head;
	struct thread_args *next;
	struct thread_args *prev;
	pthread_mutex_t *mutex;
	HostCache *cache;
	pthread_t thread_id;
	struct in_addr addr;
};

static void *thread_lookup(void *args_ptr);
static int in_addr_comp(const void *key_a, const void *key_b);
static unsigned int in_addr_hash(const void *key);
static HostCache *sharedHostCache = nil;

@implementation HostCache

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
	if((self = [super initWithKeySize:sizeof(struct in_addr) hashSlots:HC_HASHTABLE_SZ hashFunction:in_addr_hash comparisonFunction:in_addr_comp]) != nil) {
		thread_list = NULL;

		if(pthread_mutex_init(&mutex, NULL) != 0)
			goto err;

		if(pthread_attr_init(&thread_attr) != 0) {
			(void)pthread_mutex_destroy(&mutex);
			goto err;
		}

		if(pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED) != 0) {
			(void)pthread_mutex_destroy(&mutex);
			(void)pthread_attr_destroy(&thread_attr);
			goto err;
		}
	}
	return self;

	err:
		[super dealloc];
		return nil;
}

- (void)lookupComplete:(id)sender
{
	[[NSNotificationCenter defaultCenter] postNotificationName:PPHostCacheHostNameLookupCompleteNotification object:self];
}

- (NSString *)hostWithAddressASync:(struct in_addr *)addr returnCode:(int *)code
{
	struct thread_args *args_item;
	id result;

	if(pthread_mutex_lock(&mutex) != 0)
		goto err;

	result = [super objectForKey:addr];

	if(result != nil) {
		if(pthread_mutex_unlock(&mutex) != 0)
			goto err;

		if(result == [NSNull null]) {
			if(code != NULL)
				*code = HOSTCACHE_NONAME;
			return nil;
		} else {
			if(code != NULL)
				*code = HOSTCACHE_SUCCESS;
			return result;
		}
	}

	for(args_item = thread_list; args_item != NULL; args_item = args_item->next) {
		if(args_item->addr.s_addr == addr->s_addr) { /* found a currently running thread */
			if(pthread_mutex_unlock(&mutex) != 0)
				goto err;
			goto inprog;
		}
	}

	/* no thread running, so add ourself to the list */
	args_item = malloc(sizeof(struct thread_args));

	/* insert args_item at the head of the list */
	args_item->next = thread_list;
	args_item->prev = NULL;
	if(thread_list != NULL)
		thread_list->prev = args_item;
	thread_list = args_item;

	/* set thread parameters */
	args_item->head = &thread_list;
	args_item->mutex = &mutex;
	args_item->cache = self;
	args_item->addr = *addr;

	if(pthread_mutex_unlock(&mutex) != 0)
		goto err;

	if(pthread_create(&args_item->thread_id, &thread_attr, thread_lookup, args_item) != 0) {
		if(pthread_mutex_lock(&mutex) == 0) { /* try to remove the list entry */
			thread_list = thread_list->next;
			if(thread_list != NULL)
				thread_list->prev = NULL;
			free(args_item);
			(void)pthread_mutex_unlock(&mutex);
		}
		goto err;
	}

	inprog:
		if(code != NULL)
			*code = HOSTCACHE_INPROG;
		return nil;

	err:
	 	if(code != NULL)
			*code = HOSTCACHE_ERROR;
		return nil;
}

/* ignores any mutexes, so do not use with hostWithAddressAsync */
- (NSString *)hostWithAddress:(struct in_addr *)addr
{
	id result;

	result = [super objectForKey:addr];

	if(result == nil) {
		char host[NI_MAXHOST];
		struct sockaddr_in sin;
		int gret;

		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
        sin.sin_addr = *addr;

		/* XXX sometime in the future, when Apple fix OS X's getnameinfo, this getnameinfo2
		   call should be replaced with a call to the libc getnameinfo */
		if((gret = getnameinfo2((struct sockaddr *)&sin, sin.sin_len, host, sizeof(host), NULL, 0, NI_NAMEREQD)) != 0) {
			if(gret != EAI_AGAIN && gret != EAI_NONAME)
				return nil; /* if an error occured then do not add a cache entry */

			result = [NSNull null];
		} else {
			if((result = [[NSString alloc] initWithUTF8String:host]) == nil)
				return nil;

			[result autorelease];
		}

		[super insertObject:result forKey:addr];
	}

	return (result == [NSNull null]) ? nil : result;
}

- (void)flush
{
	if(pthread_mutex_lock(&mutex) == 0) {
		[super flush];
		(void)pthread_mutex_unlock(&mutex);
	}
}

- (void)dealloc
{
	struct thread_args *args_free;

	if(pthread_mutex_lock(&mutex) == 0) {
		while(thread_list != NULL) {
			args_free = thread_list;
			thread_list = thread_list->next;
			(void)pthread_cancel(args_free->thread_id);
			free(args_free);
		} /* possibly enable asynchronous cancellation? */
		(void)pthread_mutex_unlock(&mutex);
	}

	(void)pthread_mutex_destroy(&mutex);
	(void)pthread_attr_destroy(&thread_attr);
	[super dealloc];
}

- (void)encodeWithCoder:(NSCoder *)coder
{
	(void)pthread_mutex_lock(&mutex);
	[super encodeWithCoder:coder];
	(void)pthread_mutex_unlock(&mutex);
}

- (id)initWithCoder:(NSCoder *)coder
{
	[super setHashFunction:in_addr_hash];
	[super setComparisonFunction:in_addr_comp];

	thread_list = NULL;

	if(pthread_mutex_init(&mutex, NULL) != 0)
		return nil;

	if(pthread_attr_init(&thread_attr) != 0) {
		(void)pthread_mutex_destroy(&mutex);
		return nil;
	}

	if(pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED) != 0) {
		(void)pthread_mutex_destroy(&mutex);
		(void)pthread_attr_destroy(&thread_attr);
		return nil;
	}

	return [super initWithCoder:coder];
}

@end

/* XXX this needs rewriting, we should use a more reliable mechanism
   for cancelling threads--possible race condition here (but masked
   by the fact that we just call exit(3) without deallocing all
   objects when we quit) */
static void *thread_lookup(void *args_ptr)
{
	struct thread_args *args;
	id result;
	int gret;
	struct sockaddr_in sin;
	char host[NI_MAXHOST];

	args = args_ptr;

	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
    sin.sin_addr = args->addr; /* no lock required, only modification to thread args is after cancellation */

	/* XXX sometime in the future, when Apple fix OS X's getnameinfo, this getnameinfo2
	   call should be replaced with a call to the libc getnameinfo */
	if((gret = getnameinfo2((struct sockaddr *)&sin, sin.sin_len, host, sizeof(host), NULL, 0, NI_NAMEREQD)) != 0) {
		if(gret != EAI_NONAME) {
			(void)pthread_mutex_lock(args->mutex);
			goto err; /* if an error occured then do not add a cache entry */
		}

		result = [NSNull null];
	} else if((result = [[NSString alloc] initWithUTF8String:host]) == nil) { /* NSString is thread-safe */
		(void)pthread_mutex_lock(args->mutex);
		goto err;
	}

	if(pthread_mutex_lock(args->mutex) != 0)
		goto err;

	pthread_testcancel();

	[args->cache insertObject:result forKey:&args->addr];

err:
	/* remove us from the list of currently running lookups */
	if(args->prev == NULL) { /* we are the list head */
		*args->head = args->next;
		if(args->next != NULL)
			(*args->head)->prev = NULL;
	} else {
		args->prev->next = args->next;
		if(args->next != NULL) /* if we are not the last item */
			args->next->prev = args->prev;
	}

	[args->cache performSelectorOnMainThread:@selector(lookupComplete:) withObject:nil waitUntilDone:NO];

	(void)pthread_mutex_unlock(args->mutex);
	free(args);
	return NULL;
}

static int in_addr_comp(const void *key_a, const void *key_b)
{
	return ((unsigned int)(((struct in_addr *)key_a)->s_addr) - (unsigned int)(((struct in_addr *)key_b)->s_addr));
}

static unsigned int in_addr_hash(const void *key)
{
	return (((struct in_addr *)key)->s_addr & HC_HASHMASK);
}
