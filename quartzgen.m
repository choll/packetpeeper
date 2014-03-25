/*
 *  quartzgen.c
 *  graphviz
 *
 *  Created by Glen Low on Tue Nov 25 2003.
 *  Copyright (c) 2003, Pixelglow Software. All rights reserved.
 *  http://www.pixelglow.com/graphviz/
 *  graphviz@pixelglow.com
 *
 *  Redistribution and use in source and binary forms, with or without modification, are permitted
 *  provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright notice, this list of conditions
 *    and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions
 *    and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *  * Neither the name of Pixelglow Software nor the names of its contributors may be used to endorse or
 *    promote products derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ApplicationServices/ApplicationServices.h>
#include <QuickTime/QuickTime.h>
#include <Quicktime/QuicktimeComponents.k.h>

#import <AppKit/NSGraphicsContext.h>

#import <Foundation/NSString.h>

#include <render.h>

//#include "quartzgen.h"

typedef struct graphics_context {
    ATSURGBAlphaColor pencolor;
    ATSURGBAlphaColor fillcolor;
    char* fontname;
    double fontsize;
    int visible;
} graphics_context;

static TECObjectRef converter = NULL;				/* Unicode text converter */
static CFMutableDictionaryRef text_cache = NULL;	/* cache of ATSUI layouts, for measuring & drawing text. */

static int onetime = TRUE;						/* whether more than one graph is being drawn */

static CGContextRef graphics = NULL;			/* graphics context to draw into */
static node_t* current_node = NULL;				/* the current node */

static double comp_scale;

#define STACKSIZE 32

static graphics_context context[STACKSIZE];
static graphics_context *current_context = context;

/* error handling */

static void check_status (char* context, OSStatus status)
{
	if (status)
		agerr (AGWARN, "%s status = %d.\n", context, status);
}

static void check_null (char* context, const void* ptr)
{
	if (!ptr)
		agerr (AGERR, "%s = null.\n", context);
}

static CFHashCode djb2_hash (char *str)
{
	CFHashCode hash = 5381;
	while (*str++)
		hash = ((hash << 5) + hash) + *str;
		
    return hash;
}

/* text cache */

typedef struct text_key {
    char* str;
    char* fontname;
    double fontsize;
} text_key;

typedef struct text_value {
    ConstUniCharArrayPtr buffer;
    ATSUStyle style;
    ATSUTextLayout layout;
} text_value;

static const void* text_key_retain (CFAllocatorRef allocator, const void *value)
{
    /* allocate fresh memory and copy from stack version */
    text_key* copy;
	check_null ("CFAllocatorAllocate", copy = CFAllocatorAllocate(allocator,sizeof(text_key),0));
	text_key* original = (text_key*) value;
	copy->str = strdup (original->str);
	copy->fontname = strdup (original->fontname);
	copy->fontsize = original->fontsize;
    return copy;
}

static void text_key_release (CFAllocatorRef allocator, const void *value)
{
	text_key* key = (text_key*) value;
	free (key->str);
	free (key->fontname);
    CFAllocatorDeallocate(allocator,(void*)value);
}

static Boolean text_key_equals (const void *value1, const void *value2)
{
    const text_key* key1 = (text_key*)value1;
    const text_key* key2 = (text_key*)value2;
    return streq(key1->str,key2->str) && streq(key1->fontname,key2->fontname) && key1->fontsize == key2->fontsize;
}

static CFHashCode text_key_hash (const void *value)
{
	/* since fontname, fontsize are likely to remain constant, we hash only on str using djb2 */
    return djb2_hash (((text_key*)value)->str);
}

static const void* text_value_retain (CFAllocatorRef allocator, const void *value)
{
    /* already allocated in get_text */
    return value;
}

static void text_value_release (CFAllocatorRef allocator, const void *value)
{
    text_value* val = (text_value*)value;
    ATSUDisposeTextLayout(val->layout);
    ATSUDisposeStyle(val->style);
	CFAllocatorDeallocate(kCFAllocatorDefault,(void*)val->buffer);   /* was allocated in get_text */
    CFAllocatorDeallocate(kCFAllocatorDefault,val);		/* was allocated in get_text */
}

static CFDictionaryKeyCallBacks text_key_callbacks = {
    0,
    text_key_retain,
    text_key_release,
    NULL,  /* copyDescription */
    text_key_equals,
    text_key_hash
};

static CFDictionaryValueCallBacks text_value_callbacks = {
    0,
    text_value_retain,
    text_value_release,
    NULL,  /* copyDescription */
    NULL /* equals */
};

text_value *fetch_text (char *str, char *fontname, double fontsize)
{
	text_key key = {str, fontname, fontsize};
    
	if(!text_cache)
		check_null ("CFDictionaryCreateMutable",
			text_cache = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &text_key_callbacks, &text_value_callbacks));
	
	text_value *value;
	if (!CFDictionaryGetValueIfPresent(text_cache, &key, (const void**)&value)) {
		check_null ("CFAllocatorAllocate", value = CFAllocatorAllocate(kCFAllocatorDefault, sizeof(text_value), 0));
		
		/* set style to matched font and given size */
		
		ATSUFontID font;
		check_status ("ATSUFindFontFromName",
			ATSUFindFontFromName(fontname,
			strlen(fontname),
			kFontPostscriptName,
			kFontNoPlatformCode,
			kFontNoScriptCode,
			kFontNoLanguageCode,
			&font));
		Fixed size = X2Fix(fontsize);
		
		ATSUAttributeTag style_tags[] = {kATSUFontTag, kATSUSizeTag};
		ByteCount style_sizes[] = {sizeof(ATSUFontID), sizeof(Fixed)};
		ATSUAttributeValuePtr style_values[] = {&font, &size};

		check_status("ATSUCreateStyle", ATSUCreateStyle(&value->style));
		check_status("ATSUSetAttributes", ATSUSetAttributes(value->style, 2, style_tags, style_sizes, style_values));
		
		/* convert str into Unicode */
		
		ByteCount ail, aol;
		ByteCount len = strlen(str);
		if(!converter)
			check_status("TECCreateConverter",
				TECCreateConverter(&converter,
				kCFStringEncodingUTF8,
				kCFStringEncodingUnicode));
		check_null("CFAllocatorAllocate", value->buffer = CFAllocatorAllocate(kCFAllocatorDefault, len ? 2*len : 1, 0));
		if(len)
			check_status("TECConvertText", TECConvertText(converter, (unsigned char *)str, len, &ail, (TextPtr)value->buffer, 2*len, &aol));
		
		/* create layout with Unicode text and style run for all text */
		UniCharCount run = kATSUToTextEnd;
		check_status("ATSUCreateTextLayoutWithTextPtr",
			ATSUCreateTextLayoutWithTextPtr(value->buffer,
			0,
			aol / 2,
			aol / 2,
			1,
			&run,
			&value->style,
			&value->layout));

		CFDictionaryAddValue(text_cache,&key,value);
    }
		
    return value;
}

static CGPathDrawingMode get_mode(int filled)
{
 	if(filled)
		return current_context->pencolor.red == current_context->fillcolor.red
			&& current_context->pencolor.green == current_context->fillcolor.green
			&& current_context->pencolor.blue == current_context->fillcolor.blue
			&& current_context->pencolor.alpha == current_context->fillcolor.alpha
			? kCGPathFill : kCGPathFillStroke;
    else
		return kCGPathStroke;
}

void
quartz_reset(void)
{
//	NSLog(@"quartz_reset");
	onetime = TRUE;
}

void quartz_begin_job_for_pdf(FILE* ofp, graph_t* g, char** lib, char* user, char* info[], point pages)
{
//	NSLog(@"quartz_begin_job_for_pdf: %f", GD_drawing(g)->scale);
}
/*
void
quartz_end_job_for_pdf(void)
{
	NSLog(@"quartz_end_job_for_pdf");
 //   if (graphics)
//		CGContextRelease(graphics);
}*/

static void begin_graph_for_pdf()
{
//	NSLog(@"begin_graph_for_pdf");
	if(onetime) {
		graphics = [[NSGraphicsContext currentContext] graphicsPort];
//		NSLog(@"begin_graph_for_pdf: NEW CONTEXT");
	}
}

void
quartz_begin_graph_for_paged_pdf(GVC_t *gvc, graph_t* g, box bb, point pb)
{
//	NSLog(@"quartz_begin_graph_for_paged_pdf: %f", GD_drawing(g)->scale);
	begin_graph_for_pdf();
}

void
quartz_end_graph(void)
{
//	NSLog(@"quartz_end_graph");
    onetime = FALSE;
}

void
begin_page()
{
	/* initialize the context stack */
	current_context = context;
	memset(&current_context->pencolor,0,sizeof(ATSURGBAlphaColor));
	memset(&current_context->fillcolor,0,sizeof(ATSURGBAlphaColor));
	current_context->fontname = NULL;
	current_context->fontsize = 0.0;
	current_context->visible = TRUE;
}

void
quartz_begin_page_for_paged_pdf(graph_t* g, point page, double scale, int rot, point offset)
{
//	NSLog(@"quartz_begin_page_for_paged_pdf: %f and %f", scale, GD_drawing(g)->scale);
	comp_scale = scale;// = 0.5;
    CGContextSaveGState(graphics);
	CGContextTranslateCTM(graphics,
	GD_drawing(g)->margin.x+offset.x * scale,
	GD_drawing(g)->margin.y+offset.y * scale);
	if(scale != 1.0)
		CGContextScaleCTM(graphics, scale, scale);

	begin_page();
}


void
quartz_end_page_for_pdf(void)
{
    CGContextRestoreGState(graphics);
}

void
quartz_begin_node(node_t* n)
{
	current_node = n;
}

void
quartz_end_node()
{
	current_node = NULL;
}

void
quartz_begin_context(void)
{
//	NSLog(@"begin context");
    CGContextSaveGState(graphics);
    ++current_context;
    *current_context = *(current_context - 1);
}

void
quartz_end_context(void)
{
    CGContextRestoreGState(graphics);
    --current_context;
}

void
quartz_set_font(char* fontname, double fontsize)
{
    current_context->fontname = fontname;
    current_context->fontsize = fontsize;
}

static void
get_color(ATSURGBAlphaColor* color, char* name)
{
	color_t coloring;
	colorxlate(name,&coloring,RGBA_WORD);
	color->red = coloring.u.rrggbbaa[0]/65535.0;
	color->green = coloring.u.rrggbbaa[1]/65535.0;
	color->blue = coloring.u.rrggbbaa[2]/65535.0;
	color->alpha =	coloring.u.rrggbbaa[3]/65535.0;
}

void
quartz_textline(point p, textline_t* str)
{
    if (current_context->visible) {
	double adj;
	
	switch (str->just) {
	    case 'l':
			adj = 0.0;
			break;
	    case 'r':
			adj = -1.0;
			break;
	    default:
		case 'n':
			adj = -0.5;
		break;
	}

	/* fetch any cached text for this string */
	text_value* text = fetch_text(str->str,current_context->fontname,current_context->fontsize);
	if (text) {
		/* associate graphics context with layout so that we can draw it */
		ATSUAttributeTag lay_tags[] = {kATSUCGContextTag};
		ByteCount lay_sizes[] = {sizeof(CGContextRef)};
		ATSUAttributeValuePtr lay_values[] = {&graphics};
		check_status ("ATSUSetLayoutControls", ATSUSetLayoutControls(text->layout,1,lay_tags,lay_sizes,lay_values));

		/* set color of text */
		ATSUAttributeTag style_tags[] = {kATSURGBAlphaColorTag};
		ByteCount style_sizes[] = {sizeof(ATSURGBAlphaColor)};
		ATSUAttributeValuePtr style_values[] = {&current_context->pencolor};
		check_status ("ATSUSetAttributes", ATSUSetAttributes(text->style,1,style_tags,style_sizes,style_values));
		
		/* draw it */
		CGContextSaveGState (graphics);
		CGContextTranslateCTM (graphics, p.x+adj*str->width, p.y);
		check_status ("ATSUDrawText", ATSUDrawText(text->layout,
			kATSUFromTextBeginning,
			kATSUToTextEnd,
			0,
			0));
		CGContextRestoreGState (graphics);
	}
    }
}

void
quartz_set_pencolor(char *name)
{
	get_color(&current_context->pencolor,name);
	CGContextSetRGBStrokeColor(graphics,
		current_context->pencolor.red,
		current_context->pencolor.green,
		current_context->pencolor.blue,
		current_context->pencolor.alpha);
}

void
quartz_set_fillcolor(char* name)
{
	get_color(&current_context->fillcolor,name);
	CGContextSetRGBFillColor(graphics,
		current_context->fillcolor.red,
		current_context->fillcolor.green,
		current_context->fillcolor.blue,
		current_context->fillcolor.alpha);
}

void
quartz_set_style(char** s)
{
    const char* line;

    while ((line = *s++))
		if (streq(line,"solid"))
			CGContextSetLineDash(graphics,0.0,0,0);
		else if (streq(line,"dashed")) {
			float dash[2];
			dash[0] = dash[1] = 9/comp_scale;
			CGContextSetLineDash(graphics,0.0,dash,2);
			}
		else if (streq(line,"dotted")) {
			float dash[2];
			dash[0] = comp_scale;
			dash[1] = 6/comp_scale;
			CGContextSetLineDash(graphics,0.0,dash,2);
			}
		else if (streq(line,"invis"))
			current_context->visible = FALSE;
		else if (streq(line,"bold"))
			CGContextSetLineWidth(graphics,2.0);
		else if (streq(line, "setlinewidth")) {
			const char *p = line;
			while (*p) p++;
			p++;
			CGContextSetLineWidth(graphics,atof(p));
		}
}

void
quartz_ellipse(point p, int rx, int ry, int filled)
{
    if (current_context->visible) {
		CGContextSaveGState(graphics);
		CGContextTranslateCTM(graphics,p.x,p.y);
		CGContextScaleCTM(graphics,rx,ry);
		CGContextBeginPath(graphics);
		CGContextAddArc(graphics,0,0,1,0,2*PI,1);
		CGContextClosePath(graphics);
		CGContextRestoreGState(graphics);
		CGContextDrawPath(graphics,get_mode(filled));
    }
}

void
quartz_polygon(point* A, int n, int filled)
{
    if (current_context->visible) {
		int j;
		
		CGContextBeginPath(graphics);
		CGContextMoveToPoint(graphics,A[0].x,A[0].y);
		for (j = 1; j < n; ++j)
			CGContextAddLineToPoint(graphics,A[j].x,A[j].y);
		CGContextClosePath(graphics);
		CGContextDrawPath(graphics,get_mode(filled));
    }
}

void
quartz_beziercurve(point* A, int n, int arrow_at_start, int arrow_at_end)
{
    if (current_context->visible) {
		int j;
		
		CGContextBeginPath(graphics);
		CGContextMoveToPoint(graphics,A[0].x,A[0].y);
		for (j = 1; j < n; j += 3)
			CGContextAddCurveToPoint(graphics,A[j].x,A[j].y,A[j+1].x,A[j+1].y,A[j+2].x,A[j+2].y);
		CGContextDrawPath(graphics,kCGPathStroke);
    }
}

void
quartz_polyline(point* A,int n)
{
    if (current_context->visible) {
		int j;
		
		CGContextBeginPath(graphics);
		CGContextMoveToPoint(graphics,A[0].x,A[0].y);
		for (j = 1; j < n; ++j)
			CGContextAddLineToPoint(graphics,A[j].x,A[j].y);
		CGContextDrawPath(graphics,kCGPathStroke);
    }
}
