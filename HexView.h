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

#ifndef _HEXVIEW_H_
#define _HEXVIEW_H_

#include <stdint.h>
#import <AppKit/NSView.h>

#define HEXVIEW_BUF_SZ		(8 * 1024)

#define HEXVIEW_FONT_SZ		0.0f		/* default font size, 0 = default */

#define HEXVIEW_MIN_BYTES	16			/* minimum number of bytes represented per line */

#define HEXVIEW_LMARGIN		7.0f		/* number of pixels in the left-hand margin */

#define HEXVIEW_SEPARATOR_CHAR	' '
#define HEXVIEW_NEWLINE_CHAR	'\n'

#define HEXVIEW_LARGE_SEPARATOR_SZ	2

#define HEXVIEW_LN_NCHARS(bytes) ((HEXVIEW_LARGE_SEPARATOR_SZ * 2) + ((((bytes) / 2) + (((bytes) % 2) != 0)) - 1) + 9 + ((bytes) * 2) + (bytes) + 1)

/* rounds up the value x to the next y unit */
#define RUPF(x, y) ((y) * ceilf((x) / (y)))

/* rounds down the value x to the next y unit */
#define RDOWNF(x, y) ((y) * floorf((x) / (y)))

/* takes the number of bytes in a packet, and the number of bytes in a line and returns the number of lines required */
#define HEXVIEW_NLINES(pbytes, lbytes) (((pbytes) / (lbytes)) + (((pbytes) % (lbytes)) ? 1 : 0))

@class NSColor;
@class NSIndexSet;
@class NSFont;
@protocol HexViewDataSource;

@interface HexView : NSView
{
	char buf[HEXVIEW_BUF_SZ];
	id <HexViewDataSource> dataSource;
	NSColor *textColor;
	NSColor *hexColor;
	NSColor *offsetColor;
	NSFont *font;
	NSSize viewSize;		/* size of the view */
	NSSize glyphSize;
	unsigned int ln_nbytes; /* number of bytes represented in a line */
	unsigned int length;	/* data source length */
	const uint8_t *bytes;	/* data source bytes */
}

/* no dealloc! mem leak */

- (void)setDataSource:(id <HexViewDataSource>)anObject;
- (id <HexViewDataSource>)dataSource;
- (void)calculateBytesPerLine;
- (void)calculateFrame;
- (void)reloadData;

- (void)setTextColor:(NSColor *)color;
- (NSColor *)textColor;
- (void)setHexColor:(NSColor *)color;
- (NSColor *)hexColor;
- (void)setOffsetColor:(NSColor *)color;
- (NSColor *)offsetColor;
- (void)setFont:(NSFont *)aFont;
- (NSFont *)font;


- (void)highlightFrom:(unsigned int)from to:(unsigned int)to;
- (void)highlightRange:(NSIndexSet *)ranges;
- (void)removeHighlight;

- (void)buildLine:(const uint8_t *)data nbytes:(unsigned int)nbytes offset:(unsigned int)offset output:(char *)output;
- (void)drawUTF8:(const char *)utf8str rect:(NSRect)rect length:(unsigned int)utf8len;

@end

/* HexView datasource protocol */

@protocol HexViewDataSource <NSObject>

- (unsigned int)length;
- (const void *)bytes;

@end

#endif /* _HEXVIEW_H_ */
