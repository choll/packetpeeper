/*
 * Packet Peeper
 * Copyright 2006, 2007, Chris E. Holloway
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

#ifndef _PPPROGRESSWINDOWCONTROLLER_H_
#define _PPPROGRESSWINDOWCONTROLLER_H_

#import <AppKit/NSWindowController.h>

@class NSProgressIndicator;
@class NSTextField;

@interface PPProgressWindowController : NSWindowController
{
	IBOutlet NSTextField *m_loadingMessage;
	IBOutlet NSProgressIndicator *m_progressIndicator;
	NSString *m_initialLoadingMessage;
	id m_delegate;
	SEL m_cancelSelector;
}

- (id)initWithLoadingMessage:(NSString *)loadingMessage delegate:(id)delegate cancelSelector:(SEL)cancelSelector;
- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo;
- (IBAction)cancelButtonPressed:(id)sender;
- (void)setLoadingMessage:(NSString *)loadingMessage;
- (void)setPercentLoaded:(double)loadedPercent;

@end

#endif
