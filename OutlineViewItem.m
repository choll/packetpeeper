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

#include <stdarg.h>
#include <objc/message.h>
#import <Foundation/NSObject.h>
#import <Foundation/NSArray.h>
#include "OutlineViewItem.h"

#import <Foundation/NSString.h>

/* OutlineCallback object private to OutlineViewItem */

@interface OutlineCallback : NSObject
{
	id target;
	SEL selector;
	void *data;
}

- (id)initWithTarget:(id)aTarget selector:(SEL)aSelector data:(void *)ptr;
- (id)performAction;

@end

@implementation OutlineViewItem

+ (OutlineViewItem *)outlineViewWithObject:(id)anObject
{
	OutlineViewItem *ret;

	ret = [[OutlineViewItem alloc] init];
	[ret addObject:anObject];

	return [ret autorelease];
}

- (id)init
{
	if((self = [super init]) != nil) {
		items = [[NSMutableArray alloc] init];
		children = nil;
	}
	return self;
}

- (void)addObject:(id)anObject
{
	if(anObject != nil)
		[items addObject:anObject];
}

- (void)removeChild:(id)anObject
{
	if(anObject != nil && children != nil)
		[children removeObject:anObject];
}

- (void)addChild:(id)anObject
{
	if(children == nil)
		children = [[NSMutableArray alloc] init];

	if(anObject != nil)
		[children addObject:anObject];
}

- (unsigned int)indexOfChild:(id)anObject
{
	return [children indexOfObject:anObject];
}

- (void)insertChild:(id)anObject atIndex:(unsigned int)index
{
	if(children == nil)
		children = [[NSMutableArray alloc] init];

	if(index <= [children count] && anObject != nil)
		[children insertObject:anObject atIndex:index];
}

- (void)addChildWithCallback:(id)aTarget selector:(SEL)aSelector data:(void *)ptr
{
	id cback;

	if(children == nil)
		children = [[NSMutableArray alloc] init];

	cback = [[OutlineCallback alloc] initWithTarget:aTarget selector:aSelector data:ptr];
	[children addObject:cback];
	[cback release];
}

- (void)addChildWithObjects:(id)firstObj, ...
{
	va_list ap;
	OutlineViewItem *child;

	if(children == nil)
		children = [[NSMutableArray alloc] init];

	child = [[OutlineViewItem alloc] init];

	for(va_start(ap, firstObj); firstObj != nil; firstObj = va_arg(ap, id))
		[child addObject:firstObj];

	[self addChild:child];
	[child release];
	va_end(ap);
}

- (BOOL)expandable
{
	return (children != nil);
}

- (unsigned int)numberOfChildren
{
	if(children)
		return [children count];
	else
		return 0;
}

- (id)childAtIndex:(int)fieldIndex
{
	id ret;

	ret = [children objectAtIndex:fieldIndex];

	if([ret isMemberOfClass:[OutlineCallback class]])
		ret = [ret performAction];

	return ret;
}

- (unsigned int)numberOfValues
{
	return [items count];
}

- (id)valueAtIndex:(int)anIndex
{
	return [items objectAtIndex:anIndex];
}

- (void)dealloc
{
	[items release];
	[children release];
	[super dealloc];
}

@end

@implementation OutlineCallback

- (id)initWithTarget:(id)aTarget selector:(SEL)aSelector data:(void *)ptr
{
	if((self = [super init]) != nil) {
		target = aTarget;
		selector = aSelector;
		data = ptr;
	}
	return self;
}

- (id)performAction
{
	return objc_msgSend(target, selector, data);
}

@end
