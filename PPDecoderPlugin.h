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

#ifndef PPDECODERPLUGIN_H_
#define PPDECODERPLUGIN_H_

#include "Describe.h"

@class NSString;
@class NSData;
@class NSArray;
@class OutlineViewItem;

@protocol PPDecoderPlugin <NSObject>

- (id)initWithModule:(NSString *)moduleName;
- (BOOL)loadModule:(NSString *)moduleName;
- (BOOL)canDecodeProtocol:(NSString *)protocol port:(unsigned int)port;
- (NSArray *)columnIdentifiers;
- (NSString *)columnStringForIndex:(unsigned int)fieldIndex data:(NSData *)data;
/* comp_data is the packet to compare against, data is 'self' */
- (NSComparisonResult)compareWith:(NSData *)comp_data atIndex:(unsigned int)fieldIndex data:(NSData *)data;
- (OutlineViewItem *)outlineViewItemTreeForData:(NSData *)data;
- (BOOL)isValidData:(NSData *)data;
- (NSString *)shortName;
- (NSString *)longName;
- (NSString *)infoForData:(NSData *)data;
- (stacklev)level;

@end

#endif
