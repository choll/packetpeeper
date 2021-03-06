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

#include "AppController.h"
#include "../Shared/Decoding/ARPDecode.h"
#include "../Shared/Decoding/EthernetDecode.h"
#include "../Shared/Decoding/ICMPDecode.h"
#include "../Shared/Decoding/IPV4Decode.h"
#include "../Shared/Decoding/IPV6Decode.h"
#include "../Shared/Decoding/LoopbackDecode.h"
#include "../Shared/Decoding/PPPDecode.h"
#include "../Shared/Decoding/PPRVIDecode.h"
#include "../Shared/Decoding/Packet.h"
#include "../Shared/Decoding/TCPDecode.h"
#include "../Shared/Decoding/UDPDecode.h"
#include "../Shared/ObjectIO/socketpath.h"
#include "../Shared/PacketPeeper.h"
#include "Filters/PPCaptureFilterManager.h"
#include "Plugins/PPDecoderPlugin.h"
#include "Plugins/PPPluginManager.h"
#include "UI Classes/ColumnIdentifier.h"
#include "UI Classes/MyDocument.h"
#include "UI Classes/MyDocumentController.h"
#include "UI Classes/PPPacketUIAdditions.h"
#include "UI Classes/PacketCaptureWindowController.h"
#include "UI Classes/TCPStreams/PPStreamsWindowController.h"
#import <AppKit/NSAlert.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSCell.h>
#import <AppKit/NSMenu.h>
#import <AppKit/NSMenuItem.h>
#import <AppKit/NSTableColumn.h>
#import <AppKit/NSTableHeaderCell.h>
#import <AppKit/NSWindow.h>
#import <AppKit/NSWorkspace.h>
#import <CoreServices/CoreServices.h>
#import <Foundation/NSArchiver.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSBundle.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSString.h>
#import <Foundation/NSUserDefaults.h>
#import <Foundation/NSValue.h>
#include <unistd.h>

/* NSApplication delegate, used by MainMenu.nib */

@implementation AppController

- (id)init
{
    if ((self = [super init]) != nil)
    {
        [[NSNotificationCenter defaultCenter]
            addObserver:self
               selector:@selector(windowDidBecomeKey:)
                   name:@"NSWindowDidBecomeKeyNotification"
                 object:nil];
        isTerminating = NO;
    }
    return self;
}

- (void)windowDidBecomeKey:(NSNotification*)aNotification
{
    NSMenu* viewMenu;
    id windowController;

    windowController = [[aNotification object] windowController];
    viewMenu = [[[NSApp mainMenu] itemWithTag:APPMENU_ITEM_VIEW_TAG] submenu];

    /* set the View->Columns menu if the window controller supports it */
    if ([windowController respondsToSelector:@selector(packetTableColumnMenu)])
    {
        [viewMenu setSubmenu:[windowController packetTableColumnMenu]
                     forItem:[viewMenu itemWithTag:APPMENU_ITEM_COLUMNS_TAG]];
    }

    /* set the View->Sort By menu if the window controller supports it */
    /* XXX TODO...	APPMENU_ITEM_SORTBY_TAG, also needs adding to nib */

    /* set the View -> Auto Scroling menu item if the window controller supports it */
    if ([windowController
            respondsToSelector:@selector(packetTableDoesAutoScroll)])
    {
        [[viewMenu itemWithTag:APPMENU_ITEM_SCROLLING_TAG]
            setState:[windowController packetTableDoesAutoScroll]];
    }
    else
    {
        MyDocument* currentDocument;
        currentDocument = [[MyDocumentController sharedDocumentController]
            documentForWindow:[aNotification object]];
        [[viewMenu itemWithTag:APPMENU_ITEM_SCROLLING_TAG]
            setState:[[currentDocument packetCaptureWindowController]
                         packetTableDoesAutoScroll]];
    }

    /* set the View -> Data Inspector menu item if the window controller supports it */
    if ([windowController
            respondsToSelector:@selector(isDataInspectorViewVisible)])
    {
        [[viewMenu itemWithTag:APPMENU_ITEM_DATA_INSPECTOR_TAG]
            setState:[windowController isDataInspectorViewVisible]];
    }
    else
    {
        MyDocument* currentDocument;
        currentDocument = [[MyDocumentController sharedDocumentController]
            documentForWindow:[aNotification object]];
        [[viewMenu itemWithTag:APPMENU_ITEM_DATA_INSPECTOR_TAG]
            setState:[[currentDocument packetCaptureWindowController]
                         isDataInspectorViewVisible]];
    }
}

/* Prevent NSApplication from opening an untitled document at application startup */
- (BOOL)applicationShouldOpenUntitledFile:(NSApplication*)sender
{
    return NO;
}

- (NSMenu*)createTCPProtocolsMenu
{
    Class decoders[] = {[LoopbackDecode class],
                        [EthernetDecode class],
                        [PPRVIDecode class],
                        [PPPDecode class],
                        [IPV4Decode class],
                        [IPV6Decode class],
                        [TCPDecode class]};

    return [self createProtocolsMenuForDecoders:decoders
                                          count:(sizeof(decoders) /
                                                 sizeof(decoders[0]))];
}

- (NSMenu*)createProtocolsMenu
{
    Class decoders[] = {[LoopbackDecode class],
                        [EthernetDecode class],
                        [PPRVIDecode class],
                        [PPPDecode class],
                        [ARPDecode class],
                        [RARPDecode class],
                        [IPV4Decode class],
                        [IPV6Decode class],
                        [ICMPDecode class],
                        [UDPDecode class],
                        [TCPDecode class]};
    NSMenu* menu;
    NSArray* plugins;
    unsigned int i, j;

    menu = [self createProtocolsMenuForDecoders:decoders
                                          count:(sizeof(decoders) /
                                                 sizeof(decoders[0]))];

    /* add plugins */

    plugins = [[PPPluginManager sharedPluginManager] pluginsList];

    for (i = 0; i < [plugins count]; ++i)
    {
        id<PPDecoderPlugin> plugin;
        NSMenu* submenu;
        NSMenuItem* item;
        NSArray* identifiers;

        plugin = [plugins objectAtIndex:i];

        if ((identifiers = [plugin columnIdentifiers]) == nil)
            continue;

        submenu = [[NSMenu alloc] init];
        item = [[NSMenuItem alloc] init];

        [item setTitle:[plugin longName]];
        [menu addItem:item];
        [menu setSubmenu:submenu forItem:item];
        [item release];

        for (j = 0; j < [identifiers count]; ++j)
        {
            item = [[NSMenuItem alloc] init];
            [item setTitle:[[identifiers objectAtIndex:j] longName]];
            [item setRepresentedObject:[identifiers objectAtIndex:j]];
            [item setAction:@selector(columnMenuAction:)];
            [submenu addItem:item];
            [item release];
        }
        [submenu release];
    }

    return menu;
}

- (NSMenu*)createProtocolsMenuForDecoders:(Class*)decoders
                                    count:(size_t)ndecoders
{
    NSArray* identifiers;
    NSMenu* menu;
    NSMenuItem* item;
    unsigned int i, j;

    /* populate the View->Columns application menu item */
    menu = [[NSMenu alloc] init];

    identifiers = [[Packet class] columnIdentifiers];

    for (j = 0; j < [identifiers count]; ++j)
    {
        item = [[NSMenuItem alloc] init];
        [item setTitle:[[identifiers objectAtIndex:j] longName]];
        [item setRepresentedObject:[identifiers objectAtIndex:j]];
        [item setAction:@selector(columnMenuAction:)];
        [menu addItem:item];
        [item release];
    }

    for (i = 0; i < ndecoders; ++i)
    {
        NSMenu* submenu;

        identifiers = [decoders[i] columnIdentifiers];
        submenu = [[NSMenu alloc] init];
        item = [[NSMenuItem alloc] init];

        [item setTitle:[decoders[i] longName]];
        [menu addItem:item];
        [menu setSubmenu:submenu forItem:item];
        [item release];

        for (j = 0; j < [identifiers count]; ++j)
        {
            item = [[NSMenuItem alloc] init];
            [item setTitle:[[identifiers objectAtIndex:j] longName]];
            [item setRepresentedObject:[identifiers objectAtIndex:j]];
            [item setAction:@selector(columnMenuAction:)];
            [submenu addItem:item];
            [item release];
        }
        [submenu release];
    }

    return [menu autorelease];
}

- (void)applicationWillFinishLaunching:(NSNotification*)aNotification
{
    [self initializeDefaults];
}

- (void)initializeDefaults
{
    NSString* column_id_stream_table[] = {
        PPSTREAMSWINDOW_STREAMS_TABLE_SRC_HOSTNAME,
        PPSTREAMSWINDOW_STREAMS_TABLE_DST_HOSTNAME,
        PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORTNAME,
        PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORTNAME,
        PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_SENT,
        PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_RECV};
    NSMutableDictionary* defaultValues;
    NSMutableArray* packetTableColumnArray;
    NSMutableArray* streamTableColumnArray;
    NSMenu* menu;
    NSMenuItem* menuItem;
    NSTableColumn* column;
    unsigned int i;

    /* using the information from the menu is kind of ugly, ought to be better than this. */

    if ((defaultValues = [[NSMutableDictionary alloc] init]) == nil)
        return;

    if ((packetTableColumnArray = [[NSMutableArray alloc] init]) == nil)
        return;

    if ((streamTableColumnArray = [[NSMutableArray alloc] init]) == nil)
        return;

    menu = [self createProtocolsMenu];

    /* set the default columns of the main window and stream windows packet table view */

    for (i = 0; i < [menu numberOfItems]; ++i)
    {
        ColumnIdentifier* currentIdentifier;

        menuItem = [menu itemAtIndex:i];
        currentIdentifier = [menuItem representedObject];

        if (![[currentIdentifier longName] isEqualToString:@"Packet number"] &&
            ![[currentIdentifier longName] isEqualToString:@"Date received"] &&
            ![[currentIdentifier longName] isEqualToString:@"Protocols"] &&
            ![[currentIdentifier longName] isEqualToString:@"Information"])
            continue;

            // XXX WONTFIX
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
        column = [[NSTableColumn alloc] initWithIdentifier:currentIdentifier];
#pragma clang diagnostic pop

        [[column headerCell] setStringValue:[currentIdentifier shortName]];
        [column setEditable:NO];
        [packetTableColumnArray addObject:column];
        [column release];
        [menuItem setState:NSOnState];
    }

    menu = [PPStreamsWindowController createStreamTableMenu];

    /* set the default columns of the stream windows stream table view */
    for (i = 0; i < (sizeof(column_id_stream_table) /
                     sizeof(column_id_stream_table[0]));
         ++i)
    {
        menuItem = [menu itemAtIndex:[menu indexOfItemWithRepresentedObject:
                                               column_id_stream_table[i]]];
        column = [[NSTableColumn alloc]
            initWithIdentifier:column_id_stream_table[i]];

        [[column headerCell] setStringValue:[menuItem title]];

        [column setEditable:NO];
        [streamTableColumnArray addObject:column];
        [column release];
        [menuItem setState:NSOnState];
    }

    [defaultValues
        setObject:[NSArchiver archivedDataWithRootObject:packetTableColumnArray]
           forKey:PPDOCUMENT_TABLEVIEW_COLUMNS_KEY];
    [defaultValues
        setObject:[NSArchiver archivedDataWithRootObject:packetTableColumnArray]
           forKey:PPSTREAMSWINDOW_PACKETTABLEVIEW_COLUMNS_KEY];
    [defaultValues
        setObject:[NSArchiver archivedDataWithRootObject:streamTableColumnArray]
           forKey:PPSTREAMSWINDOW_STREAMTABLEVIEW_COLUMNS_KEY];
    [defaultValues setObject:[NSNumber numberWithBool:YES]
                      forKey:PPDOCUMENT_DATA_INSPECTOR];
    [defaultValues setObject:[NSNumber numberWithBool:NO]
                      forKey:PPDOCUMENT_AUTOSCROLLING];
    [defaultValues setObject:[NSNumber numberWithBool:NO]
                      forKey:PPSTREAMSWINDOW_AUTOSCROLLING];
    [defaultValues setObject:[NSNumber numberWithBool:NO]
                      forKey:CAPTURE_SETUP_PROMISC];
    [defaultValues setObject:[NSNumber numberWithBool:YES]
                      forKey:CAPTURE_SETUP_REALTIME];
    [defaultValues setObject:[NSNumber numberWithBool:NO]
                      forKey:PPTCPSTREAMCONTROLLER_IP_DROP_BAD_CHECKSUMS];
    [defaultValues setObject:[NSNumber numberWithBool:NO]
                      forKey:PPTCPSTREAMCONTROLLER_TCP_DROP_BAD_CHECKSUMS];
    [defaultValues setObject:@"en0" forKey:CAPTURE_SETUP_INTERFACE];
    [defaultValues
        setObject:[NSNumber numberWithFloat:DEFAULT_UI_UPDATE_FREQUENCY]
           forKey:CAPTURE_SETUP_UPDATE_FREQUENCY];
    [defaultValues setObject:[NSNumber numberWithInt:BS_HUGE]
                      forKey:CAPTURE_SETUP_BUFSIZE];

    [[NSUserDefaults standardUserDefaults] registerDefaults:defaultValues];

    [defaultValues release];
    [packetTableColumnArray release];
    [streamTableColumnArray release];
}

- (void)applicationWillTerminate:(NSNotification*)aNotification
{
    [[PPCaptureFilterManager sharedCaptureFilterManager] saveFilters];
    [[NSUserDefaults standardUserDefaults] synchronize];
    (void)unlink(SOCKETPATH);
    isTerminating = YES;
}

- (BOOL)applicationIsTerminating
{
    return isTerminating;
}

- (IBAction)showHelp:(id)sender
{
    [[NSWorkspace sharedWorkspace]
        openFile:[[NSBundle mainBundle] pathForResource:@"UserGuide"
                                                 ofType:@"pdf"]];
}

- (IBAction)showPreferencePanel:(id)sender
{
    NSLog(@"Preference panel");
}

- (IBAction)showPluginsFolder:(id)sender
{
    [[NSWorkspace sharedWorkspace]
        openFile:[[NSBundle mainBundle] builtInPlugInsPath]];
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [super dealloc];
}

@end
