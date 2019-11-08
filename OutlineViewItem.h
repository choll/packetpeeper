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

#ifndef _OUTLINEVIEWITEM_H_
#define _OUTLINEVIEWITEM_H_

#import <Foundation/NSObject.h>
#include <stddef.h>

@class NSObject;
@class NSArray;
@class NSMutableArray;
@protocol NSObject;
@protocol OutlineViewItem;

@protocol OutlineViewItem <NSObject>
- (BOOL)expandable;
- (size_t)numberOfChildren;
- (id)childAtIndex:(int)fieldIndex;
- (size_t)numberOfValues;
- (id)valueAtIndex:(int)anIndex;
@end

@interface OutlineViewItem : NSObject <OutlineViewItem>
{
    NSMutableArray* items;
    NSMutableArray* children;
}

+ (OutlineViewItem*)outlineViewWithObject:(id)anObject;
- (void)addObject:(id)anObject;
- (void)removeChild:(id)anObject;
- (void)addChild:(id)anObject;
- (void)insertChild:(id)anObject atIndex:(unsigned int)index;
- (void)addChildWithCallback:(id)aTarget
                    selector:(SEL)aSelector
                        data:(void*)ptr;
- (void)addChildWithObjects:(id)firstObj, ...;
@end

#endif /* _OUTLINEVIEWITEM_H_ */
