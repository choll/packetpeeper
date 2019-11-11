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

#include "PPPluginWrapper.h"
#include "PPDecoderPlugin.h"
#include <Foundation/NSData.h>
#import <Foundation/NSObject.h>

@implementation PPPluginWrapper

- (id)initWithData:(NSData*)data plugin:(id<PPDecoderPlugin>)plugin
{
    if ((self = [super init]) != nil)
    {
        m_data = [data retain];
        m_plugin = [plugin retain];
    }
    return self;
}

- (id<PPDecoderPlugin>)plugin
{
    return m_plugin;
}

- (NSData*)data
{
    return m_data;
}

/* Describe protocol methods */

+ (NSString*)shortName
{
    return @"PPPluginWrapper";
}

+ (NSString*)longName
{
    return @"PPPluginWrapper";
}

- (NSString*)shortName
{
    return [m_plugin shortName];
}

- (NSString*)longName
{
    return [m_plugin longName];
}

- (NSString*)info
{
    return [m_plugin infoForData:m_data];
}

- (stacklev)level
{
    return SL_DATALINK;
}

/* OutlineViewItem protocol methods */

- (BOOL)expandable
{
    id<OutlineViewItem> outlineTree;

    if ((outlineTree = [m_plugin outlineViewItemTreeForData:m_data]) == nil)
        return NO;

    return [outlineTree expandable];
}

- (size_t)numberOfChildren
{
    id<OutlineViewItem> outlineTree;

    if ((outlineTree = [m_plugin outlineViewItemTreeForData:m_data]) == nil)
        return 0;

    return [outlineTree numberOfChildren];
}

- (id)childAtIndex:(int)fieldIndex
{
    id<OutlineViewItem> outlineTree;

    if ((outlineTree = [m_plugin outlineViewItemTreeForData:m_data]) == nil)
        return nil;

    return [outlineTree childAtIndex:fieldIndex];
}

- (size_t)numberOfValues
{
    id<OutlineViewItem> outlineTree;

    if ((outlineTree = [m_plugin outlineViewItemTreeForData:m_data]) == nil)
        return 0;

    return [outlineTree numberOfValues];
}

- (id)valueAtIndex:(int)index
{
    id<OutlineViewItem> outlineTree;

    if ((outlineTree = [m_plugin outlineViewItemTreeForData:m_data]) == nil)
        return nil;

    return [outlineTree valueAtIndex:index];
}

/* ColumnIdentifier protocol methods */

+ (NSArray*)columnIdentifiers
{
    return nil;
}

- (NSString*)columnStringForIndex:(unsigned int)fieldIndex
{
    return [m_plugin columnStringForIndex:fieldIndex data:m_data];
}

- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex
{
    return [m_plugin compareWith:[obj data] atIndex:fieldIndex data:m_data];
}

- (void)dealloc
{
    [m_data release];
    [m_plugin release];
    [super dealloc];
}

/* Decode protocol methods, this is implemented to provide a consistent interface for
   decoders. These are never called. The Decode protocol should be altered to accomodate
   plugins properly */

- (id)initWithData:(NSData*)dataVal parent:(id<PPDecoderParent>)parentVal
{
    return nil;
}

- (void)setParent:(id<PPDecoderParent>)parentVal
{
}

- (size_t)frontSize
{
    return 0;
}

- (size_t)rearSize
{
    return 0;
}

- (Class)nextLayer
{
    return Nil;
}

@end
