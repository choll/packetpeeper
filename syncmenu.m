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

#include "syncmenu.h"
#import <AppKit/NSCell.h>
#import <AppKit/NSMenu.h>
#import <Foundation/NSArray.h>

void syncMenu(NSMenu* menu, NSMutableArray* identifiers)
{
    unsigned int i, j;

    for (i = 0; i < [menu numberOfItems]; ++i)
    {
        NSMenuItem* item;

        item = [menu itemAtIndex:i];

        if ([item isSeparatorItem])
            continue;

        if (![item hasSubmenu])
        {
            if ([identifiers count] == 0)
            {
                [item setState:NSOffState];
            }
            else
            {
                for (j = 0; j < [identifiers count]; ++j)
                {
                    if ([[item representedObject]
                            isEqual:[identifiers objectAtIndex:j]])
                    {
                        [item setState:NSOnState];
                        [identifiers removeObjectAtIndex:j];
                        goto item_found;
                    }
                }

                [item setState:NSOffState];

            item_found:
                continue;
            }
        }
        else
            syncMenu([item submenu], identifiers);
    } /* for loop i */
}
