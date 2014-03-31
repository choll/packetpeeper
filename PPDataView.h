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

#ifndef PPDATAVIEW_H_
#define PPDATAVIEW_H_

#include <inttypes.h>
#import <AppKit/NSView.h>

@class NSFont;
@class NSColor;
@class PPDataViewOffsetColumn;
@class PPDataViewHexColumn;
@class PPDataViewASCIIColumn;
@protocol PPDataViewDataSource;

@interface PPDataViewAbstractBase : NSView {
	id <PPDataViewDataSource>	m_dataSource;
	NSFont						*m_font;
	NSColor						*m_textColor;
}

- (void)setDataSource:(id <PPDataViewDataSource>)dataSource;
- (id <PPDataViewDataSource>)dataSource;
- (void)reloadDataSource;

- (void)setFont:(NSFont *)font;
- (NSFont *)font;

- (void)setTextColor:(NSColor *)color;
- (NSColor *)textColor;

@end

@interface PPDataView : PPDataViewAbstractBase {
	PPDataViewOffsetColumn		*m_offsetColumnView;
	PPDataViewHexColumn			*m_hexDataView;
	PPDataViewASCIIColumn		*m_asciiDataView;
}

- (void)setOffsetColumnTextColor:(NSColor *)color;
- (void)setHexColumnTextColor:(NSColor *)color;
- (void)setASCIIColumnTextColor:(NSColor *)color;

- (NSColor *)offsetColumntextColor;
- (NSColor *)hexColumntextColor;
- (NSColor *)ASCIIColumntextColor;

- (void)setOffsetColumnVisible:(BOOL)flag;
- (void)setShowHexColumnVisible:(BOOL)flag;
- (void)setShowASCIIColumnVisible:(BOOL)flag;
- (BOOL)offsetColumnVisible;
- (BOOL)hexColumnVisible;
- (BOOL)asciiColumnVisible;

@end

@interface PPDataViewOffsetColumn : PPDataViewAbstractBase {

}

@end

@interface PPDataViewHexColumn : PPDataViewAbstractBase {

}

@end

@interface PPDataViewASCIIColumn : PPDataViewAbstractBase {

}

@end

@protocol PPDataViewDataSource

- (unsigned long long)length;
- (uint8_t)byteAtIndex:(unsigned long long)index;
- (unsigned long long)bytesAtIndex:(unsigned long long)index nbytes:(unsigned long long)nbytes bytes:(const void **)bytes;
- (unsigned long long)colorAtIndex:(unsigned long long)index nbytes:(unsigned long long)nbytes color:(NSColor *)color;

@end

#endif
