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

#ifndef _PPAPPCONTROLLER_H_
#define _PPAPPCONTROLLER_H_

#import <Breakpad/Breakpad.h>
#import <Foundation/NSObject.h>

@class NSApplication;
@class NSNotification;
@class NSMenu;
@class MyDocument;

@interface AppController : NSObject
{
    BOOL isTerminating;
    BreakpadRef breakpad;
}

- (void)windowDidBecomeKey:(NSNotification*)aNotification;
- (BOOL)applicationShouldOpenUntitledFile:(NSApplication*)sender;
- (NSMenu*)createTCPProtocolsMenu;
- (NSMenu*)createProtocolsMenu;
- (NSMenu*)createProtocolsMenuForDecoders:(Class*)decoders
                                    count:(size_t)ndecoders;
- (void)applicationWillFinishLaunching:(NSNotification*)aNotification;
- (void)initializeDefaults;
- (NSApplicationTerminateReply)applicationShouldTerminate:
    (NSApplication*)sender;
- (void)applicationWillTerminate:(NSNotification*)aNotification;
- (BOOL)applicationIsTerminating;
- (IBAction)showHelp:(id)sender;
- (IBAction)showPreferencePanel:(id)sender;
- (IBAction)showPluginsFolder:(id)sender;

@end

#endif /* _PPAPPCONTROLLER_H_ */
