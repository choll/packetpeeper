/*
 * Packet Peeper
 * Copyright 2008 Chris E. Holloway
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

#ifndef PPCAPTUREFILTERMANAGER_H_
#define PPCAPTUREFILTERMANAGER_H_

@class NSObject;
@class NSArray;
@class PPCaptureFilter;
@class NSMutableDictionary;

@interface PPCaptureFilterManager : NSObject
{
	NSMutableDictionary *m_filters;
}

+ (PPCaptureFilterManager *)sharedCaptureFilterManager;
- (PPCaptureFilter *)filterForName:(NSString *)name;
- (void)addFilter:(PPCaptureFilter *)filter;
- (void)removeFilter:(PPCaptureFilter *)filter;
- (void)saveFilters;
- (NSArray *)allFilters;

@end

#endif
