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

#include "CaptureSetupWindowController.h"
#include "ErrorStack.h"
#include "Interface.h"
#include "MyDocument.h"
#include "MyDocumentController.h"
#include "PPDataQuantityFormatter.h"
#include "PacketPeeper.h"
#include "pktap.h"
#import <AppKit/NSApplication.h>
#import <AppKit/NSButton.h>
#import <AppKit/NSDatePicker.h>
#import <AppKit/NSMatrix.h>
#import <AppKit/NSPopUpButton.h>
#import <AppKit/NSSlider.h>
#import <AppKit/NSStepper.h>
#import <AppKit/NSTextField.h>
#import <AppKit/NSWindow.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSDate.h>
#import <Foundation/NSString.h>
#import <Foundation/NSUserDefaults.h>

@implementation CaptureSetupWindowController

- (id)init
{
    if ((self = [super initWithWindowNibName:@"CaptureSetupSheet"]) != nil)
    {
        interfaces = nil;
    }
    return self;
}

- (void)windowDidLoad
{
    NSUserDefaults* defaults;
    NSString* defaultInterface;
    PPDataQuantityFormatter* dataFormatter;
    unsigned int defaultIndex;

    defaults = [NSUserDefaults standardUserDefaults];

    [[self window] setExcludedFromWindowsMenu:YES];

    [interfacePopUp removeAllItems];

    if (interfaces == nil)
        interfaces = [[Interface liveInterfaces] retain];

    if (interfaces == nil || [interfaces count] == 0)
    {
        [[MyDocumentController sharedDocumentController] cancelHelper];
        [[ErrorStack sharedErrorStack]
            pushError:@"Could not obtain list of network interfaces"
               lookup:Nil
                 code:0
             severity:ERRS_ERROR];
        [[self document] displayErrorStack:[ErrorStack sharedErrorStack]
                                     close:YES];
        [interfaces release];
        return;
    }

    defaultInterface = [defaults stringForKey:CAPTURE_SETUP_INTERFACE];
    defaultIndex = 0;

    for (unsigned int i = 0; i < [interfaces count]; ++i)
    {
        [interfacePopUp
            addItemWithTitle:[[interfaces objectAtIndex:i] description]];
        if (defaultInterface != nil &&
            [defaultInterface
                isEqualToString:[[interfaces objectAtIndex:i] shortName]])
            defaultIndex = i;
    }

    if (defaultIndex >= [interfacePopUp numberOfItems])
        defaultIndex = 0;

    [interfacePopUp selectItemAtIndex:defaultIndex];

    if ([[interfaces objectAtIndex:defaultIndex] loopback] ||
        [[interfaces objectAtIndex:defaultIndex] linkType] == DLT_PKTAP)
    {
        [promiscuousCheckBox setEnabled:NO];
        [promiscuousCheckBox setState:NO];
    }
    else if ([[interfaces objectAtIndex:defaultIndex] promisc])
    {
        [promiscuousCheckBox setEnabled:NO];
        [promiscuousCheckBox setState:YES];
    }
    else
    {
        [promiscuousCheckBox
            setState:[defaults boolForKey:CAPTURE_SETUP_PROMISC]];
    }

    [realTimeCheckBox setState:[defaults boolForKey:CAPTURE_SETUP_REALTIME]];
    [bufferLengthSlider
        setIntegerValue:[defaults integerForKey:CAPTURE_SETUP_BUFSIZE]];
    [updateFrequencyTextField
        setFloatValue:[defaults floatForKey:CAPTURE_SETUP_UPDATE_FREQUENCY]];

    [stopTimeDatePicker setMinDate:[NSDate date]];

    if ((dataFormatter = [[PPDataQuantityFormatter alloc] init]) != nil)
    {
        [stopDataTextField setFormatter:dataFormatter];
        [dataFormatter release];
    }

    [super windowDidLoad];
}

- (void)sheetDidEnd:(NSWindow*)sheet
         returnCode:(NSModalResponse)returnCode
        contextInfo:(void*)contextInfo
{
    NSUserDefaults* defaults;
    NSDate* stopDate;
    Interface* selectedInterface;
    unsigned long numberOfPackets;
    unsigned long long numberOfBytes;

    if (returnCode != NSModalResponseOK)
    {
        /* inform the doc controller that the user cancelled, so it may free
		   the authorization reference */
        [[MyDocumentController sharedDocumentController] cancelHelper];
        [[self document] close];
        return;
    }

    defaults = [NSUserDefaults standardUserDefaults];
    selectedInterface =
        [interfaces objectAtIndex:[interfacePopUp indexOfSelectedItem]];

    [defaults setBool:[promiscuousCheckBox state] forKey:CAPTURE_SETUP_PROMISC];
    [defaults setBool:[realTimeCheckBox state] forKey:CAPTURE_SETUP_REALTIME];
    [defaults setObject:[selectedInterface shortName]
                 forKey:CAPTURE_SETUP_INTERFACE];
    [defaults setInteger:[bufferLengthSlider intValue]
                  forKey:CAPTURE_SETUP_BUFSIZE];
    [defaults setFloat:[updateFrequencyTextField floatValue]
                forKey:CAPTURE_SETUP_UPDATE_FREQUENCY];

    if ([stopTimeCheckBox state] == NSOnState)
        stopDate = [stopTimeDatePicker dateValue];
    else
        stopDate = nil;

    if ([stopPacketsCheckBox state] == NSOnState)
        numberOfPackets =
            [[stopPacketsTextField objectValue] unsignedLongValue];
    else
        numberOfPackets = 0;

    if ([stopDataCheckBox state] == NSOnState)
        numberOfBytes = [[stopDataTextField objectValue] unsignedLongLongValue];
    else
        numberOfBytes = 0;

    /* read in the settings and send results to MyDocument */
    [[self document] startCaptureOn:selectedInterface
                      isPromiscuous:[promiscuousCheckBox state]
                         isRealTime:[realTimeCheckBox state]
                       bufferLength:[bufferLengthSlider intValue]
                    updateFrequency:[updateFrequencyTextField floatValue]
                   stopAfterPackets:numberOfPackets
                      stopAfterDate:stopDate
                      stopAfterData:numberOfBytes
                  stopAfterMatchAll:([[stopConditionPopUp selectedItem] tag] ==
                                     PPCAPTUREWINDOW_STOPMODE_ALL_TAG)
                             filter:[self filter]];

    [[self document] removeWindowController:self];
}

/* Interface actions */

- (IBAction)interfacePopUpSelected:(id)sender
{
    NSInteger itemIndex;

    if ((itemIndex = [sender indexOfSelectedItem]) == -1)
        return;

    const BOOL isLoopback = [[interfaces objectAtIndex:itemIndex] loopback];
    const BOOL isPromisc = [[interfaces objectAtIndex:itemIndex] promisc];
    const BOOL isPkTap =
        [[interfaces objectAtIndex:itemIndex] linkType] == DLT_PKTAP;

    /* a loopback interface does not support promiscuous mode, so turn off the
       checkbox and prevent the user from changing it */
    if (isLoopback || isPkTap)
    {
        [promiscuousCheckBox setEnabled:NO];
        [promiscuousCheckBox setState:NO];
    }
    else if (isPromisc)
    {
        [promiscuousCheckBox setEnabled:NO];
        [promiscuousCheckBox setState:YES];
    }
    else
    {
        [promiscuousCheckBox setEnabled:YES];
    }
}

- (IBAction)startButtonPressed:(id)sender
{
    [[[self window] sheetParent] endSheet:[self window]
                               returnCode:NSModalResponseOK];
    // Window controller has now been dealloced--not sure if this is the
    // correct approach, possibly the completionHandler block should autorelease?
}

- (IBAction)cancelButtonPressed:(id)sender
{
    [[[self window] sheetParent] endSheet:[self window]
                               returnCode:NSModalResponseCancel];
    // Window controller has now been dealloced--see above
}

- (IBAction)stopConditionCheckBox:(id)sender
{
    BOOL state;

    state = ([sender state] == NSOnState);

    if (sender == stopPacketsCheckBox)
        [stopPacketsTextField setEnabled:state];
    else if (sender == stopTimeCheckBox)
        [stopTimeDatePicker setEnabled:state];
    else if (sender == stopDataCheckBox)
        [stopDataTextField setEnabled:state];
}

- (void)dealloc
{
    [interfaces release];
    [super dealloc];
}

@end
