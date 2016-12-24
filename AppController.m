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

#include <unistd.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSUserDefaults.h>
#import <Foundation/NSBundle.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSValue.h>
#import <Foundation/NSArchiver.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSTableColumn.h>
#import <AppKit/NSTableHeaderCell.h>
#import <AppKit/NSWindow.h>
#import <AppKit/NSMenu.h>
#import <AppKit/NSAlert.h>
#import <AppKit/NSMenuItem.h>
#import <AppKit/NSCell.h>
#import <AppKit/NSWorkspace.h>
#import <CoreServices/CoreServices.h>
#include "LoopbackDecode.h"
#include "EthernetDecode.h"
#include "PPRVIDecode.h"
#include "Packet.h"
#include "PPPacketUIAdditons.h"
#include "PPPDecode.h"
#include "ARPDecode.h"
#include "IPV4Decode.h"
#include "IPV6Decode.h"
#include "ICMPDecode.h"
#include "UDPDecode.h"
#include "TCPDecode.h"
#include "PPPluginManager.h"
#include "PPDecoderPlugin.h"
#include "MyDocumentController.h"
#include "PacketCaptureWindowController.h"
#include "PPCaptureFilterManager.h"
#include "PPStreamsWindowController.h"
#include "MyDocument.h"
#include "ColumnIdentifier.h"
#include "socketpath.h"
#include "AppController.h"
#include "PacketPeeper.h"

/* NSApplication delegate, used by MainMenu.nib */

static BreakpadRef InitBreakpad(void);

@implementation AppController

- (id)init
{
	if((self = [super init]) != nil) {
		[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(windowDidBecomeKey:) name:@"NSWindowDidBecomeKeyNotification" object:nil];
		isTerminating = NO;
        breakpad = 0;
	}
	return self;
}

- (void)windowDidBecomeKey:(NSNotification *)aNotification
{
    NSMenu *viewMenu;
    id windowController;

    windowController = [[aNotification object] windowController];
    viewMenu = [[[NSApp mainMenu] itemWithTag:APPMENU_ITEM_VIEW_TAG] submenu];

    /* set the View->Columns menu if the window controller supports it */
    if([windowController respondsToSelector:@selector(packetTableColumnMenu)]) {
        [viewMenu setSubmenu:[windowController packetTableColumnMenu]
            forItem:[viewMenu itemWithTag:APPMENU_ITEM_COLUMNS_TAG]];
    }

    /* set the View->Sort By menu if the window controller supports it */
    /* XXX TODO...	APPMENU_ITEM_SORTBY_TAG, also needs adding to nib */

    /* set the View -> Auto Scroling menu item if the window controller supports it */
    if([windowController respondsToSelector:@selector(packetTableDoesAutoScroll)]) {
        [[viewMenu itemWithTag:APPMENU_ITEM_SCROLLING_TAG] setState:[windowController packetTableDoesAutoScroll]];
    } else {
        MyDocument *currentDocument;
        currentDocument = [[MyDocumentController sharedDocumentController] documentForWindow:[aNotification object]];
        [[viewMenu itemWithTag:APPMENU_ITEM_SCROLLING_TAG] setState:
            [[currentDocument packetCaptureWindowController] packetTableDoesAutoScroll]];
    }

    /* set the View -> Data Inspector menu item if the window controller supports it */
    if([windowController respondsToSelector:@selector(isDataInspectorViewVisible)]) {
        [[viewMenu itemWithTag:APPMENU_ITEM_DATA_INSPECTOR_TAG] setState:[windowController isDataInspectorViewVisible]];
    } else {
        MyDocument *currentDocument;
        currentDocument = [[MyDocumentController sharedDocumentController] documentForWindow:[aNotification object]];
        [[viewMenu itemWithTag:APPMENU_ITEM_DATA_INSPECTOR_TAG] setState:
            [[currentDocument packetCaptureWindowController] isDataInspectorViewVisible]];
    }
}

/* Prevent NSApplication from opening an untitled document at application startup */
- (BOOL)applicationShouldOpenUntitledFile:(NSApplication *)sender
{
    return NO;
}

- (NSMenu *)createTCPProtocolsMenu
{
	Class decoders[] = {[LoopbackDecode class],
						[EthernetDecode class],
                        [PPRVIDecode class],
						[PPPDecode class],
						[IPV4Decode class],
						[IPV6Decode class],
						[TCPDecode class]};

	return [self createProtocolsMenuForDecoders:decoders count:(sizeof(decoders) / sizeof(decoders[0]))];
}

- (NSMenu *)createProtocolsMenu
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
	NSMenu *menu;
	NSArray *plugins;
	unsigned int i, j;

	menu = [self createProtocolsMenuForDecoders:decoders count:(sizeof(decoders) / sizeof(decoders[0]))];

	/* add plugins */

	plugins = [[PPPluginManager sharedPluginManager] pluginsList];

	for(i = 0; i < [plugins count]; ++i) {
		id <PPDecoderPlugin> plugin;
		NSMenu *submenu;
		NSMenuItem *item;
		NSArray *identifiers;

		plugin = [plugins objectAtIndex:i];

		if((identifiers = [plugin columnIdentifiers]) == nil)
			continue;

		submenu = [[NSMenu alloc] init];
		item = [[NSMenuItem alloc] init];

		[item setTitle:[plugin longName]];
		[menu addItem:item];
		[menu setSubmenu:submenu forItem:item];
		[item release];

		for(j = 0; j < [identifiers count]; ++j) {
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

- (NSMenu *)createProtocolsMenuForDecoders:(Class *)decoders count:(size_t)ndecoders
{
	NSArray *identifiers;
	NSMenu *menu;
	NSMenuItem *item;
	unsigned int i, j;

	/* populate the View->Columns application menu item */
	menu = [[NSMenu alloc] init];

	identifiers = [[Packet class] columnIdentifiers];

	for(j = 0; j < [identifiers count]; ++j) {
		item = [[NSMenuItem alloc] init];
		[item setTitle:[[identifiers objectAtIndex:j] longName]];
		[item setRepresentedObject:[identifiers objectAtIndex:j]];
		[item setAction:@selector(columnMenuAction:)];
		[menu addItem:item];
		[item release];
	}

	for(i = 0; i < ndecoders; ++i) {
		NSMenu *submenu;

		identifiers = [decoders[i] columnIdentifiers];
		submenu = [[NSMenu alloc] init];
		item = [[NSMenuItem alloc] init];

		[item setTitle:[decoders[i] longName]];
		[menu addItem:item];
		[menu setSubmenu:submenu forItem:item];
		[item release];

		for(j = 0; j < [identifiers count]; ++j) {
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

- (void)applicationWillFinishLaunching:(NSNotification *)aNotification
{
	[self initializeDefaults];
}

- (void)initializeDefaults
{
	NSString *column_id_stream_table[] = {PPSTREAMSWINDOW_STREAMS_TABLE_SRC_HOSTNAME,
										  PPSTREAMSWINDOW_STREAMS_TABLE_DST_HOSTNAME,
										  PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORTNAME,
										  PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORTNAME,
										  PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_SENT,
										  PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_RECV};
	NSMutableDictionary *defaultValues;
	NSMutableArray *packetTableColumnArray;
	NSMutableArray *streamTableColumnArray;
	NSMenu *menu;
	NSMenuItem *menuItem;
	NSTableColumn *column;
	unsigned int i;

	/* delete the users preferences to avoid incompatibility issues between release 1 and 2 */
	if([[NSUserDefaults standardUserDefaults] floatForKey:PP_PREFS_VERSION_NUMBER_KEY] < PP_VERSION_NUMBER) {
		[[NSUserDefaults standardUserDefaults] removePersistentDomainForName:@"Packet Peeper"];
		[[NSUserDefaults standardUserDefaults] setFloat:PP_VERSION_NUMBER forKey:PP_PREFS_VERSION_NUMBER_KEY];
		[[NSUserDefaults standardUserDefaults] synchronize];
	}

	/* using the information from the menu is kind of ugly, ought to be better than this. */

	if((defaultValues = [[NSMutableDictionary alloc] init]) == nil)
		return;

	if((packetTableColumnArray = [[NSMutableArray alloc] init]) == nil)
		return;

	if((streamTableColumnArray = [[NSMutableArray alloc] init]) == nil)
		return;

	menu = [self createProtocolsMenu];

	/* set the default columns of the main window and stream windows packet table view */

	for(i = 0; i < [menu numberOfItems]; ++i) {
		ColumnIdentifier *currentIdentifier;

		menuItem = [menu itemAtIndex:i];
		currentIdentifier = [menuItem representedObject];

		if(![[currentIdentifier longName] isEqualToString:@"Packet number"] &&
		   ![[currentIdentifier longName] isEqualToString:@"Date received"] &&
		   ![[currentIdentifier longName] isEqualToString:@"Protocols"] &&
		   ![[currentIdentifier longName] isEqualToString:@"Information"])
			continue;

        // XXX WONTFIX
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
		column = [[NSTableColumn alloc] initWithIdentifier:currentIdentifier];
#pragma clang diagnostic pop

		[[column headerCell] takeStringValueFrom:[currentIdentifier shortName]];
		[column setEditable:NO];
		[packetTableColumnArray addObject:column];
		[column release];
		[menuItem setState:NSOnState];
	}

	/* XXX todo: add TCPDecode @"Source Hostname" and @"Destination Hostname" to the defaults */

	menu = [PPStreamsWindowController createStreamTableMenu];

	/* set the default columns of the stream windows stream table view */
	for(i = 0; i < (sizeof(column_id_stream_table) / sizeof(column_id_stream_table[0])); ++i) {
		menuItem = [menu itemAtIndex:[menu indexOfItemWithRepresentedObject:column_id_stream_table[i]]];
		column = [[NSTableColumn alloc] initWithIdentifier:column_id_stream_table[i]];

		[[column headerCell] takeStringValueFrom:[menuItem title]];

		[column setEditable:NO];
		[streamTableColumnArray addObject:column];
		[column release];
		[menuItem setState:NSOnState];
	}

	[defaultValues setObject:[NSArchiver archivedDataWithRootObject:packetTableColumnArray] forKey:PPDOCUMENT_TABLEVIEW_COLUMNS_KEY];
	[defaultValues setObject:[NSArchiver archivedDataWithRootObject:packetTableColumnArray] forKey:PPSTREAMSWINDOW_PACKETTABLEVIEW_COLUMNS_KEY];
	[defaultValues setObject:[NSArchiver archivedDataWithRootObject:streamTableColumnArray] forKey:PPSTREAMSWINDOW_STREAMTABLEVIEW_COLUMNS_KEY];
	[defaultValues setObject:[NSNumber numberWithBool:YES] forKey:PPDOCUMENT_DATA_INSPECTOR];
	[defaultValues setObject:[NSNumber numberWithBool:NO] forKey:PPDOCUMENT_AUTOSCROLLING];
	[defaultValues setObject:[NSNumber numberWithBool:NO] forKey:PPSTREAMSWINDOW_AUTOSCROLLING];
	[defaultValues setObject:[NSNumber numberWithBool:NO] forKey:CAPTURE_SETUP_PROMISC];
	[defaultValues setObject:[NSNumber numberWithBool:YES] forKey:CAPTURE_SETUP_REALTIME];
	[defaultValues setObject:[NSNumber numberWithBool:NO] forKey:PPTCPSTREAMCONTROLLER_IP_DROP_BAD_CHECKSUMS];
	[defaultValues setObject:[NSNumber numberWithBool:NO] forKey:PPTCPSTREAMCONTROLLER_TCP_DROP_BAD_CHECKSUMS];
	[defaultValues setObject:@"en0" forKey:CAPTURE_SETUP_INTERFACE];
	[defaultValues setObject:[NSNumber numberWithFloat:DEFAULT_UI_UPDATE_FREQUENCY] forKey:CAPTURE_SETUP_UPDATE_FREQUENCY];
	[defaultValues setObject:[NSNumber numberWithInt:BS_HUGE] forKey:CAPTURE_SETUP_BUFSIZE];

	[[NSUserDefaults standardUserDefaults] registerDefaults:defaultValues];

	[defaultValues release];
	[packetTableColumnArray release];
	[streamTableColumnArray release];
}

// See https://code.google.com/p/google-breakpad/wiki/MacBreakpadStarterGuide
- (void)awakeFromNib {
    breakpad = InitBreakpad();
}

// See https://code.google.com/p/google-breakpad/wiki/MacBreakpadStarterGuide
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender
{
    BreakpadRelease(breakpad);
    return NSTerminateNow;
}

- (void)applicationWillTerminate:(NSNotification *)aNotification
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
	[[NSWorkspace sharedWorkspace] openFile:[[NSBundle mainBundle] pathForResource:@"UserGuide" ofType:@"pdf"]];
}

- (IBAction)showPreferencePanel:(id)sender
{
	NSLog(@"Preference panel");
}

- (IBAction)showPluginsFolder:(id)sender
{
	[[NSWorkspace sharedWorkspace] openFile:[[NSBundle mainBundle] builtInPlugInsPath]];
}

- (void)dealloc
{
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	[super dealloc];
}

@end

// See https://code.google.com/p/google-breakpad/wiki/MacBreakpadStarterGuide
static BreakpadRef InitBreakpad(void)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    BreakpadRef breakpad = 0;
    NSDictionary *plist = [[NSBundle mainBundle] infoDictionary];
    if (plist) {
        // Note: version 1.0.0.4 of the framework changed the type of the argument
        // from CFDictionaryRef to NSDictionary * on the next line:
        breakpad = BreakpadCreate(plist);
    }
    [pool release];
    return breakpad;
}

