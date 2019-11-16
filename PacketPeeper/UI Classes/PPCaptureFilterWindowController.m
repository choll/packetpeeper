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

#include "PPCaptureFilterWindowController.h"
#include "../Filters/PPCaptureFilter.h"
#include "../Filters/PPCaptureFilterFormatter.h"
#include "../Filters/PPCaptureFilterManager.h"
#include "../Filters/PPHexNumberFormatter.h"
#include "MyDocument.h"
#import <AppKit/NSApplication.h>
#import <AppKit/NSComboBox.h>
#import <AppKit/NSTextField.h>
#import <AppKit/NSWindow.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSString.h>
#import <Foundation/NSValue.h>

@implementation PPCaptureFilterWindowController

- (id)init
{
    if ((self = [super initWithWindowNibName:@"PPCaptureFilterSheet"]) != nil)
    {
        filters = nil;
    }
    return self;
}

- (PPCaptureFilter*)filter
{
    id temp = [filterTextField objectValue];
    if ([temp isKindOfClass:[PPCaptureFilter class]])
        return temp;
    return nil;
}

- (void)windowDidLoad
{
    PPCaptureFilterFormatter* filterFormatter;
    PPHexNumberFormatter* hexFormatter;

    [[self window] setExcludedFromWindowsMenu:YES];

    if ((filterFormatter = [[PPCaptureFilterFormatter alloc] init]) != nil)
    {
        [filterTextField setFormatter:filterFormatter];
        [filterFormatter release];
    }

    if ((hexFormatter = [[PPHexNumberFormatter alloc] init]) != nil)
    {
        [filterNetmaskTextField setFormatter:hexFormatter];
        [hexFormatter release];
    }

    /* should save the last filter? */

    filters = [[[PPCaptureFilterManager sharedCaptureFilterManager] allFilters]
        retain];

    [filterTextField setDelegate:self];

    [filterNameComboBox setDataSource:self];
    [filterNameComboBox setDelegate:self];

    [applyButton setEnabled:NO];
}

- (void)sheetDidEnd:(NSWindow*)sheet
         returnCode:(NSModalResponse)returnCode
        contextInfo:(void*)contextInfo
{
    if (returnCode == NSModalResponseOK)
        [[self document] setCaptureFilter:[self filter]];
    [[self document] removeWindowController:self];
}

/* NSControl delegate methods */

- (BOOL)control:(NSControl*)control
    didFailToFormatString:(NSString*)string
         errorDescription:(NSString*)error
{
    [filterErrorTextField
        setStringValue:[NSString stringWithFormat:@"Error: %@", error]];
    [applyButton setEnabled:NO];
    return NO;
}

- (void)control:(NSControl*)control
    didFailToValidatePartialString:(NSString*)string
                  errorDescription:(NSString*)error
{
    [filterErrorTextField
        setStringValue:[NSString stringWithFormat:@"Error: %@", error]];
    [applyButton setEnabled:NO];
}

- (void)controlTextDidChange:(NSNotification*)aNotification
{
    if ([filterTextField objectValue] != nil)
    {
        [filterErrorTextField setStringValue:@"Filter OK"];
        [applyButton setEnabled:YES];
    }
}

/* NSComboBox data source methods */

- (NSInteger)numberOfItemsInComboBox:(NSComboBox*)comboBox
{
    return [filters count];
}

- (id)comboBox:(NSComboBox*)comboBox
    objectValueForItemAtIndex:(NSInteger)itemIndex
{
    return [[filters objectAtIndex:itemIndex] name];
}

/* NSComboBox delegate methods */

- (void)comboBoxSelectionDidChange:(NSNotification*)notification
{
    NSInteger itemIndex;

    if ((itemIndex = [filterNameComboBox indexOfSelectedItem]) == -1)
        return;

    [filterTextField setObjectValue:[filters objectAtIndex:itemIndex]];
    [filterNetmaskTextField
        setObjectValue:[NSNumber
                           numberWithUnsignedLong:[[filters
                                                      objectAtIndex:itemIndex]
                                                      netmask]]];
    [self controlTextDidChange:notification];
}

- (IBAction)saveFilterButtonPressed:(id)sender
{
    PPCaptureFilterManager* filterManager;
    PPCaptureFilter* filter;

    if ([[filterNameComboBox stringValue] length] < 1)
    {
        [filterErrorTextField
            setStringValue:@"Error: Please enter a filter name"];
        return;
    }

    if ([[filterTextField stringValue] length] < 1)
    {
        [filterErrorTextField
            setStringValue:@"Error: No filter text entered to save"];
        return;
    }

    filterManager = [PPCaptureFilterManager sharedCaptureFilterManager];

    filter = [filterTextField objectValue];
    [filter setName:[filterNameComboBox stringValue]];
    [filter setNetmask:[[filterNetmaskTextField objectValue] unsignedIntValue]];

    [filterManager addFilter:filter];

    [filters release];
    filters = [[[PPCaptureFilterManager sharedCaptureFilterManager] allFilters]
        retain];

    [filterErrorTextField setStringValue:@"Filter saved"];
}

- (IBAction)deleteFilterButtonPressed:(id)sender
{
    PPCaptureFilterManager* filterManager;
    PPCaptureFilter* filter;

    filterManager = [PPCaptureFilterManager sharedCaptureFilterManager];

    if ((filter = [filterManager
             filterForName:[filterNameComboBox stringValue]]) == nil)
        return;

    if ([filters count] < 2)
    {
        /* no more items, clear all */
        [filterNameComboBox setStringValue:@""];
        [filterTextField setStringValue:@""];
        [filterNetmaskTextField setStringValue:@""];
    }
    else
    {
        NSInteger itemIndex;

        /* select item below, or next lowest if we were bottom item */

        if ([filterNameComboBox indexOfSelectedItem] < 1)
            itemIndex = 0;
        else
            itemIndex = [filterNameComboBox indexOfSelectedItem] - 1;

        [filterNameComboBox selectItemAtIndex:itemIndex];
    }

    [filterManager removeFilter:filter];

    [filters release];
    filters = [[[PPCaptureFilterManager sharedCaptureFilterManager] allFilters]
        retain];

    [filterErrorTextField setStringValue:@""];
}

- (IBAction)applyButtonPressed:(id)sender
{
    [[[self window] sheetParent] endSheet:[self window]
                               returnCode:NSModalResponseOK];
}

- (IBAction)cancelButtonPressed:(id)sender
{
    [[[self window] sheetParent] endSheet:[self window]
                               returnCode:NSModalResponseCancel];
}

- (void)dealloc
{
    [filters release];
    [super dealloc];
}

@end
