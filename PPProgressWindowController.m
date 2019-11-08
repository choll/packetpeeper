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

#include "PPProgressWindowController.h"
#include "MyDocument.h"
#import <AppKit/NSProgressIndicator.h>
#import <AppKit/NSTextField.h>
#import <AppKit/NSWindow.h>

@implementation PPProgressWindowController

- (id)initWithLoadingMessage:(NSString*)loadingMessage
                    delegate:(id)delegate
              cancelSelector:(SEL)cancelSelector
{
    if ((self = [super initWithWindowNibName:@"ProgressSheet"]) != nil)
    {
        m_initialLoadingMessage = loadingMessage;
        m_delegate = delegate;
        m_cancelSelector = cancelSelector;
    }
    return self;
}

- (void)windowDidLoad
{
    [self setLoadingMessage:m_initialLoadingMessage];
    [m_initialLoadingMessage release];
    m_initialLoadingMessage = nil;
    [m_progressIndicator startAnimation:self];
}

- (IBAction)cancelButtonPressed:(id)sender
{
    [m_delegate performSelector:m_cancelSelector];
}

- (void)setLoadingMessage:(NSString*)loadingMessage
{
    [m_loadingMessage setStringValue:loadingMessage];
}

- (void)setPercentLoaded:(double)loadedPercent
{
    [m_progressIndicator setIndeterminate:NO];
    [m_progressIndicator setDoubleValue:loadedPercent];
}

- (void)dealloc
{
    [m_initialLoadingMessage release];
    [super dealloc];
}

@end
