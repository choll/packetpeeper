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

#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#import <Foundation/NSException.h>
#import <Foundation/NSAttributedString.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSString.h>
#import <AppKit/NSColor.h>
#import <AppKit/NSFont.h>
#import <AppKit/NSStringDrawing.h>
#import <AppKit/NSScrollView.h>
#include "HexView.h"

@implementation HexView

- (id)initWithFrame:(NSRect)rect
{
	if((self = [super initWithFrame:rect]) != nil) {
		dataSource = nil;
		ln_nbytes = HEXVIEW_MIN_BYTES;
		[[self enclosingScrollView] setPostsFrameChangedNotifications:YES];
		[self setTextColor:[NSColor blackColor]];
		[self setOffsetColor:[NSColor greenColor]];
		[self setHexColor:[NSColor redColor]];
		[self setFont:[NSFont userFixedPitchFontOfSize:HEXVIEW_FONT_SZ]];
	}
	return self;
}

- (void)awakeFromNib
{
	[self calculateBytesPerLine];
	[self calculateFrame];
}

- (void)setDataSource:(id <HexViewDataSource>)anObject
{
	/* we do not retain the data source (to avoid retain cycles) */
	dataSource = anObject;
	[self reloadData];
}

- (id <HexViewDataSource>)dataSource
{
	return dataSource;
}

- (void)calculateBytesPerLine
{
	NSSize size;
	unsigned int cwidth;

	size = [[self enclosingScrollView] contentSize];

	if(HEXVIEW_LMARGIN >= size.width)
		return;

	size.width -= HEXVIEW_LMARGIN;

	cwidth = (unsigned int)(size.width / glyphSize.width);

	if(HEXVIEW_LN_NCHARS(HEXVIEW_MIN_BYTES) < cwidth) {
		ln_nbytes = (unsigned int)((cwidth - (9 + (HEXVIEW_LARGE_SEPARATOR_SZ * 2))) / 3.5);
		ln_nbytes -= ln_nbytes % 2;
	}
}

- (void)calculateFrame
{
	viewSize.width = HEXVIEW_LMARGIN + glyphSize.width * (HEXVIEW_LN_NCHARS(ln_nbytes) - 1);
	viewSize.height = glyphSize.height * HEXVIEW_NLINES(length, ln_nbytes);

	[self setFrameSize:viewSize];
	[self setNeedsDisplay:YES];
}

- (void)reloadData
{
	length = [dataSource length];
	bytes = [dataSource bytes];
	[self calculateFrame];
}

- (void)setTextColor:(NSColor *)color
{
	[color retain];
	[textColor release];
	textColor = color;
	[self setNeedsDisplay:YES];
}

- (NSColor *)textColor
{
	return textColor;
}

- (void)setHexColor:(NSColor *)color
{
	[color retain];
	[hexColor release];
	hexColor = color;
	[self setNeedsDisplay:YES];
}

- (NSColor *)hexColor
{
	return hexColor;
}

- (void)setOffsetColor:(NSColor *)color
{
	[color retain];
	[offsetColor release];
	offsetColor = color;
	[self setNeedsDisplay:YES];
}

- (NSColor *)offsetColor
{
	return offsetColor;
}

- (void)setFont:(NSFont *)aFont
{
	NSDictionary *attributes;

	attributes = [[NSDictionary alloc] initWithObjectsAndKeys:aFont, NSFontAttributeName, nil];
	[aFont retain];
	[font release];
	font = aFont;
	/* 0-1, A-F are expected to be the same width and height */
	glyphSize = [@"A" sizeWithAttributes:attributes];
	[attributes release];
	[self calculateBytesPerLine];
	[self calculateFrame];
}

- (NSFont *)font
{
	return font;
}

- (void)highlightFrom:(unsigned int)from to:(unsigned int)to
{
}

- (void)highlightRange:(NSIndexSet *)ranges
{
}

- (void)removeHighlight
{
}

- (BOOL)isFlipped
{
	return YES;
}

- (void)drawRect:(NSRect)rect
{
	unsigned int startl;
	unsigned int endl;
	unsigned int offset;
	unsigned int i, j;

	if(length == 0 || bytes == NULL)
		return;

	NSAssert(glyphSize.height > 0.0, @"Invalid font size\n");
	NSAssert(HEXVIEW_LN_NCHARS(ln_nbytes) <= HEXVIEW_BUF_SZ, @"Line size too large");

	/* adjust the region we're drawing to so that it encompasses whole lines only */
	rect.origin.x = HEXVIEW_LMARGIN;
	rect.origin.y = RDOWNF(rect.origin.y, glyphSize.height);
	rect.size.width = viewSize.width;
	rect.size.height = RUPF(rect.size.height, glyphSize.height) + glyphSize.height;

	/* calculate the lines that are in the new rect */
	startl = rect.origin.y / glyphSize.height;
	endl = MIN((rect.origin.y + rect.size.height) / glyphSize.height, HEXVIEW_NLINES(length, ln_nbytes));

	for(i = 0; (startl + i) < endl;) {
		for(j = 0; ((j + 1) * HEXVIEW_LN_NCHARS(ln_nbytes)) < HEXVIEW_BUF_SZ && (startl + i) < endl; ++i, ++j) {
			offset = ((startl + i) * ln_nbytes);

			if((startl + i + 1) == HEXVIEW_NLINES(length, ln_nbytes) && length % ln_nbytes) /* if the last line is less than a full line */
				[self buildLine:bytes + offset nbytes:(length % ln_nbytes) offset:offset output:buf + (j * HEXVIEW_LN_NCHARS(ln_nbytes))];
			else 
				[self buildLine:bytes + offset nbytes:ln_nbytes offset:offset output:buf + (j * HEXVIEW_LN_NCHARS(ln_nbytes))];
		}

		[self drawUTF8:buf rect:rect length:j * HEXVIEW_LN_NCHARS(ln_nbytes)];

		if((startl + i) < endl) {
			rect.origin.y += glyphSize.height * j;
			rect.size.height -= glyphSize.height * j;
		}
	}

	/* draw dividing lines here */
}

- (void)viewDidEndLiveResize
{
	[self calculateBytesPerLine];
	[self calculateFrame];
}

- (void)buildLine:(const uint8_t *)data nbytes:(unsigned int)nbytes offset:(unsigned int)offset output:(char *)output
{
	const unsigned char base16[16] = "0123456789ABCDEF";
	unsigned int j;
	uint32_t offseth;

	offseth = offset;

	for(j = 0; j < 8; ++j) {
		*output++ = base16[(offseth & 0xF0000000) >> 28];
		offseth <<= 4;
	}

	/* little endian, >>= 4 and mask by 0xF with no 28 shift. */

	*output++ = 'h';

	for(j = 0; j < HEXVIEW_LARGE_SEPARATOR_SZ; ++j)
		*output++ = HEXVIEW_SEPARATOR_CHAR;

	for(j = 0; j < nbytes; ++j) {
		*output++ = base16[(data[j] >> 4) & 0xF];
		*output++ = base16[data[j] & 0xF];

		if(((j+1) % 2) == 0)
			*output++ = HEXVIEW_SEPARATOR_CHAR;
	}

	/* fill in space if line incomplete */
	for(; j < ln_nbytes; ++j) {
		*output++ = '.';
		*output++ = '.';
		if(((j+1) % 2) == 0)
			*output++ = HEXVIEW_SEPARATOR_CHAR;
	}

	for(j = 0; j < HEXVIEW_LARGE_SEPARATOR_SZ - 1; ++j)
		*output++ = HEXVIEW_SEPARATOR_CHAR;

	for(j = 0; j < nbytes; ++j) 
		*output++ = (isprint(data[j]) ? data[j] : '.');

	/* fill in space if line incomplete */
	for(; j < ln_nbytes; ++j) {
		*output++ = ' ';
	}

	*output = HEXVIEW_NEWLINE_CHAR;
}

- (void)drawUTF8:(const char *)utf8str rect:(NSRect)rect length:(unsigned int)utf8len
{
	NSString *str;
	NSDictionary *attributes;

	/* XXX initWithBytesNoCopy is 10.3 only */
	str = [[NSString alloc] initWithBytesNoCopy:(void *)utf8str length:utf8len encoding:NSUTF8StringEncoding freeWhenDone:NO];
	attributes = [[NSDictionary alloc] initWithObjectsAndKeys:font, NSFontAttributeName, nil];

	[str drawInRect:rect withAttributes:attributes];

	[str release];
	[attributes release];
}

- (void)dealloc
{
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	[textColor release];
	[hexColor release];
	[offsetColor release];
	[font release];
	[super dealloc];
}

@end
