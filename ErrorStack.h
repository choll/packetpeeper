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

#ifndef _ERRORSTACK_H_
#define _ERRORSTACK_H_

#import <Foundation/NSObject.h>

#define ERRS_ERROR		0
#define ERRS_WARNING	1

// XXX config.h

#define ERRORSTACK_SZ	5

@class NSString;
@protocol ErrorStack;

struct es_elem {
/*	id selfVar;
	NSString *file;
	NSString *function;*/
	NSString *description;
	Class lookup;
/*	unsigned int line;*/
	unsigned int code;
	unsigned int severity;
};

@protocol ErrorStack <NSObject>

+ (NSString *)stringForErrorCode:(unsigned int)code;
+ (NSString *)errorDomain;

@end

@interface ErrorStack : NSObject <NSCoding>
{
	struct es_elem *elems;	/* array of error elements */
	unsigned int index;		/* index of next free slot in elems */
	unsigned int size;		/* size of elems */
}

/* Returns the single instance of ErrorStack, creating it first if it doesnt exist */
+ (ErrorStack *)sharedErrorStack;

/* Does actual work for adding an error to the stack, private method */
- (void)pushError:/*(id)selfVar
				   file:(NSString *)file
				   function:(NSString *)function
				   line:(unsigned int)line
				   description:*/(NSString *)description
				   lookup:(Class)lookup
				   code:(unsigned int)code
				   severity:(unsigned int)severity;

/* remove the last Error from the stack */
- (void)pop;

/* remove all errors from the stack */
- (void)reset;

/* returns the size of the stack, the number of elements present in it */
- (unsigned int)size;

/* return the string resulting from looking up the errors code with the lookup class */
- (NSString *)lookupString;

/* returns the description string at the top of the stack */
- (NSString *)descriptionString;

/* returns the class variable used for lookups at the top of the stack, for a class error */
- (Class)lookup;

/* returns the domain of the error at the top of the stack */
- (NSString *)domain;

/* return the code of the error at the top of the stack */
- (unsigned int)code;

/* return the severity of the error at the top of the stack */
- (unsigned int)severity;

@end

@interface PosixError : NSObject <ErrorStack>
@end

#endif /* _ERRORSTACK_H_ */
