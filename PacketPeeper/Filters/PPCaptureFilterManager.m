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

#include "PPCaptureFilterManager.h"
#include "PPCaptureFilter.h"
#include "../../Shared/PacketPeeper.h"
#import <Foundation/NSArchiver.h>
#import <Foundation/NSData.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSString.h>
#import <Foundation/NSUserDefaults.h>

static PPCaptureFilterManager* sharedCaptureFilterManager = nil;

@implementation PPCaptureFilterManager

- (id)init
{
    NSDictionary* savedFilters;
    NSData* savedFiltersData;

    if ((self = [super init]) != nil)
    {
        m_filters = [[NSMutableDictionary alloc] init];

        if ((savedFiltersData = [[NSUserDefaults standardUserDefaults]
                 objectForKey:PPCAPTUREFILTERMANAGER_SAVED_FILTERS]) != nil)
        {
            if ((savedFilters = [NSUnarchiver
                     unarchiveObjectWithData:savedFiltersData]) != nil)
            {
                [m_filters addEntriesFromDictionary:savedFilters];
            }
        }
    }
    return self;
}

+ (PPCaptureFilterManager*)sharedCaptureFilterManager
{
    if (sharedCaptureFilterManager == nil)
        sharedCaptureFilterManager = [[PPCaptureFilterManager alloc] init];

    return sharedCaptureFilterManager;
}

- (PPCaptureFilter*)filterForName:(NSString*)name
{
    return [m_filters objectForKey:name];
}

- (void)addFilter:(PPCaptureFilter*)filter
{
    [m_filters setObject:filter forKey:[filter name]];
    [self saveFilters]; // save to disk immediately
}

- (void)removeFilter:(PPCaptureFilter*)filter
{
    [m_filters removeObjectForKey:[filter name]];
    [self saveFilters]; // save to disk immediately
}

- (void)saveFilters
{
    NSDictionary* temp;

    temp = [[NSDictionary alloc] initWithDictionary:m_filters];
    [[NSUserDefaults standardUserDefaults]
        setObject:[NSArchiver archivedDataWithRootObject:temp]
           forKey:PPCAPTUREFILTERMANAGER_SAVED_FILTERS];
    [temp release];
}

- (NSArray*)allFilters
{
    return [m_filters allValues];
}

- (void)dealloc
{
    [m_filters release];
    [super dealloc];
}

@end
