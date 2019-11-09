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

#ifndef _COLUMNIDENTIFIER_H_
#define _COLUMNIDENTIFIER_H_

#import <Foundation/NSObject.h>

@class NSString;
@class NSArray;
@protocol PPDecoderPlugin;

@protocol ColumnIdentifier <NSObject>
+ (NSArray*)columnIdentifiers;
- (NSString*)columnStringForIndex:(unsigned int)fieldIndex;
- (NSComparisonResult)compareWith:(id)obj atIndex:(unsigned int)fieldIndex;
@end

@interface ColumnIdentifier : NSObject <NSCoding>
{
    Class
        decoder; /* decoder that this column belongs to (if built-in decoder)  */
    id<PPDecoderPlugin>
        plugin; /* decoder that this column belongs to (if plugin decoder) */
    unsigned int index;  /* index value used by decoder */
    NSString* longName;  /* long name used in menu list */
    NSString* shortName; /* short name used in column header */
}

- (id)initWithDecoder:(Class)decoderVal
                index:(unsigned int)indexVal
             longName:(NSString*)longNameVal
            shortName:(NSString*)shortNameVal;
- (id)initWithPlugin:(id<PPDecoderPlugin>)pluginVal
               index:(unsigned int)indexVal
            longName:(NSString*)longNameVal
           shortName:(NSString*)shortNameVal;
- (Class)decoder;
- (id<PPDecoderPlugin>)plugin;
- (unsigned int)index;
- (NSString*)longName;
- (NSString*)shortName;
- (NSString*)identifier;

@end

#endif
