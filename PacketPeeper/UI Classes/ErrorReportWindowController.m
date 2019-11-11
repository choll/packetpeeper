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

#include "ErrorReportWindowController.h"
#include "../../Shared/ErrorStack.h"
#import <AppKit/NSApplication.h>
#import <AppKit/NSButton.h>
#import <AppKit/NSTextField.h>
#import <AppKit/NSTextView.h>
#import <AppKit/NSWindow.h>

@implementation ErrorReportWindowController

- (id)init
{
    if ((self = [super initWithWindowNibName:@"ErrorReportSheet"]) != nil)
    {
        errorStack = nil;
    }
    return self;
}

- (void)windowDidLoad
{
    [[self window] setExcludedFromWindowsMenu:YES];

    /* no specific stack specified, so use the shared one */
    if (!errorStack)
        [self setErrorStack:[ErrorStack sharedErrorStack]];

    [self displayData];
    [errorStack pop];
    if ([errorStack size])
        [nextButton setEnabled:YES];
}

- (void)setErrorStack:(ErrorStack*)errorStackVal
{
    [errorStackVal retain];
    [errorStack release];
    errorStack = errorStackVal;
}

- (void)displayData
{
    NSString* domainStr;
    NSString* descriptionStr;
    NSString* reasonStr;

    if ((domainStr = [errorStack domain]) == nil)
        domainStr = @"Unknown";

    if ((descriptionStr = [errorStack descriptionString]) == nil)
        descriptionStr = @"<None available>";

    if ((reasonStr = [errorStack lookupString]) == nil)
        reasonStr = @"<None available>";

    [domain setStringValue:domainStr];
    [description setString:descriptionStr];
    [reason setString:reasonStr];
}

- (IBAction)dismissButtonPressed:(id)sender
{
    [[[self window] sheetParent] endSheet:[self window]
                               returnCode:NSModalResponseCancel];
}

- (IBAction)nextButtonPressed:(id)sender
{
    [self displayData];
    [errorStack pop];
    if (![errorStack size])
        [nextButton setEnabled:NO];
}

- (void)dealloc
{
    [errorStack release];
    [super dealloc];
}

@end
