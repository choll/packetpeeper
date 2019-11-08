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

#include "PPPyDecoderPlugin.h"
#include "ColumnIdentifier.h"
#include "OutlineViewItem.h"
#include "PPDecoderPlugin.h"
#include "strfuncs.h"
#import <Foundation/NSArray.h>
#import <Foundation/NSBundle.h>
#import <Foundation/NSData.h>
#import <Foundation/NSObject.h>
#import <Foundation/NSString.h>
#include <Python.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <machine/endian.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

enum data_type
{
    TYPE_NONE,
    TYPE_PAD_BYTE,
    TYPE_CHAR,
    TYPE_STRING,
    TYPE_INT8,
    TYPE_UINT8,
    TYPE_INT16,
    TYPE_UINT16,
    TYPE_INT32,
    TYPE_UINT32,
    TYPE_INT64,
    TYPE_UINT64,
    TYPE_FLOAT,
    TYPE_DOUBLE,
    TYPE_IPv4_ADDR
};

enum endian_modifier
{
    NATIVE_ORDER_NATIVE_ALIGN,
    NATIVE_ORDER_STD_ALIGN,
    LITTLE_ORDER_STD_ALIGN,
    BIG_ORDER_STD_ALIGN
};

static PyMODINIT_FUNC init_packetpeeper_module(void);
static PyObject* pp_size(PyObject* self, PyObject* args);
static PyObject* pp_unpack(PyObject* self, PyObject* args);
static size_t pp_unpack_parse_endian_modifier(
    const char* format, enum endian_modifier* endian_modifier);
static size_t pp_unpack_parse_repeat_modifier(
    const char* format, unsigned int* repeat_modifier);
static size_t
pp_unpack_parse_type(const char* format, enum data_type* data_type);
static OutlineViewItem* buildOutlineViewItemTreeFromList(PyObject* list);
static uint16_t bswap16(uint16_t int16);
static uint32_t bswap32(uint32_t int32);
static uint64_t bswap64(uint64_t int64);

static PyMethodDef ppMethods[] = {
    {"size", pp_size, METH_VARARGS, "Number of bytes in target data"},
    {"unpack", pp_unpack, METH_VARARGS, "Unpack target data"},
    {NULL, NULL, 0, NULL}};

#if (BYTE_ORDER == BIG_ENDIAN)
#define be16toh(x) (x)
#define be32toh(x) (x)
#define be64toh(x) (x)
#define le16toh(x) bswap16(x)
#define le32toh(x) bswap32(x)
#define le64toh(x) bswap64(x)
#elif (BYTE_ORDER == LITTLE_ENDIAN)
#define be16toh(x) bswap16(x)
#define be32toh(x) bswap32(x)
#define be64toh(x) bswap64(x)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#else
#error "Unknown byte order"
#endif

@implementation PPPyDecoderPlugin

- (id)init
{
    if ((self = [super init]) != nil)
    {
        if (!Py_IsInitialized())
        {
            Py_Initialize();
            init_packetpeeper_module();
            /* gcc barfs if we try to pass this directly to PyRun_SimpleString() */
            const char* temp = [[NSString
                stringWithFormat:@"import sys\nsys.path.append(\"%@\")\n",
                                 [[NSBundle mainBundle] builtInPlugInsPath]]
                UTF8String];
            if (PyRun_SimpleString(temp) != 0)
                return nil;
        }

        module = NULL;
        shortNameFunc = NULL;
        longNameFunc = NULL;
        infoFunc = NULL;
        descriptionTreeFunc = NULL;
        isValidDataFunc = NULL;
        columnIdentifiersFunc = NULL;
        columnStringForIndexFunc = NULL;
        compareColumnForIndex = NULL;
    }
    return self;
}

- (id)initWithModule:(NSString*)moduleName
{
    if ((self = [self init]) != nil)
    {
        if (![self loadModule:moduleName])
        {
            [self dealloc];
            return nil;
        }
    }
    return self;
}

- (BOOL)loadModule:(NSString*)moduleName
{
    PyObject* name;
    unsigned int i;
    struct
    {
        const char* funcName;
        PyObject** funcObject;
    } funcs[] = {{"canDecodeProtocol", &canDecodeProtocolFunc},
                 {"shortName", &shortNameFunc},
                 {"longName", &longNameFunc},
                 {"info", &infoFunc},
                 {"descriptionTree", &descriptionTreeFunc},
                 {"isValidData", &isValidDataFunc},
                 {"columnIdentifiers", &columnIdentifiersFunc},
                 {"columnStringForIndex", &columnStringForIndexFunc},
                 {"compareColumnForIndex", &compareColumnForIndex}};

    [self clear];

    if (moduleName == NULL)
        return NO;

    if ((name = PyString_FromString([moduleName UTF8String])) == NULL)
        return NO;

    module = PyImport_Import(name);

    Py_DECREF(name);

    if (module == NULL)
    {
        NSLog(@"Failed to load module '%@'", moduleName);
        PyErr_Print();
        return NO;
    }

    for (i = 0; i < sizeof(funcs) / sizeof(funcs[0]); ++i)
    {
        if (!PyObject_HasAttrString(module, (char*)funcs[i].funcName))
        {
            NSLog(
                @"Function '%@.%s' is missing", moduleName, funcs[i].funcName);
            continue;
        }
        if ((*funcs[i].funcObject = PyObject_GetAttrString(
                 module, (char*)funcs[i].funcName)) == NULL)
        {
            NSLog(
                @"Failed to load function '%@.%s'",
                moduleName,
                funcs[i].funcName);
            continue;
        }
        if (!PyCallable_Check(*funcs[i].funcObject))
        {
            NSLog(
                @"Symbol '%@.%s' is not callable",
                moduleName,
                funcs[i].funcName);
            continue;
        }
    }

    return YES;
}

- (BOOL)canDecodeProtocol:(NSString*)protocol port:(unsigned int)port
{
    PyObject* args;
    PyObject* value;
    BOOL ret;

    if (protocol == nil)
        return NO;

    ret = NO;
    args = NULL;
    value = NULL;

    if ((args = PyTuple_New(2)) == NULL)
        goto err;

    if ((value = PyString_FromString([protocol UTF8String])) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 0, value) != 0)
        goto err;

    if ((value = PyLong_FromUnsignedLong(port)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 1, value) != 0)
        goto err;

    if ((value = PyObject_CallObject(canDecodeProtocolFunc, args)) == NULL)
    {
        PyErr_Print();
        goto err;
    }

    if (PyBool_Check(value))
        ret = (value == Py_True) ? YES : NO;

err:
    Py_XDECREF(args);
    Py_XDECREF(value);

    return ret;
}

- (NSString*)shortName
{
    NSString* ret;
    PyObject* args;
    PyObject* value;
    const char* temp;

    if ((args = PyTuple_New(0)) == NULL)
        return nil;

    if ((value = PyObject_CallObject(shortNameFunc, args)) == NULL)
    {
        PyErr_Print();
        return nil;
    }

    ret = nil;

    if (value != NULL && PyString_Check(value))
    {
        if ((temp = PyString_AsString(value)) != NULL)
            ret = [[NSString alloc] initWithUTF8String:temp];
    }

    Py_DECREF(args);
    Py_XDECREF(value);

    return [ret autorelease];
}

- (NSString*)longName
{
    NSString* ret;
    PyObject* args;
    PyObject* value;
    const char* temp;

    if ((args = PyTuple_New(0)) == NULL)
        return nil;

    if ((value = PyObject_CallObject(longNameFunc, args)) == NULL)
    {
        PyErr_Print();
        return nil;
    }

    ret = nil;

    if (value != NULL && PyString_Check(value))
    {
        if ((temp = PyString_AsString(value)) != NULL)
            ret = [[NSString alloc] initWithUTF8String:temp];
    }

    Py_DECREF(args);
    Py_XDECREF(value);

    return [ret autorelease];
}

- (NSString*)infoForData:(NSData*)data
{
    NSString* ret;
    PyObject* args;
    PyObject* value;
    const char* temp;

    ret = nil;
    args = NULL;
    value = NULL;

    if ((args = PyTuple_New(1)) == NULL)
        return nil;

    if ((value = PyLong_FromVoidPtr(data)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 0, value) != 0)
        goto err;

    if ((value = PyObject_CallObject(infoFunc, args)) == NULL)
    {
        PyErr_Print();
        goto err;
    }

    if (value != NULL && PyString_Check(value))
    {
        if ((temp = PyString_AsString(value)) != NULL)
            ret = [[NSString alloc] initWithUTF8String:temp];
    }

err:
    Py_DECREF(args);
    Py_XDECREF(value);

    return [ret autorelease];
}

- (stacklev)level
{
    return SL_APPLICATION;
}

- (NSArray*)columnIdentifiers
{
    NSMutableArray* ret;
    ColumnIdentifier* column;
    PyObject* args;
    PyObject* value;
    unsigned int i;

    if ((args = PyTuple_New(0)) == NULL)
        return nil;

    if ((value = PyObject_CallObject(columnIdentifiersFunc, args)) == NULL)
    {
        PyErr_Print();
        return nil;
    }

    ret = nil;

    if (value != NULL && PyList_Check(value))
    {
        ret = [[NSMutableArray alloc] init];

        for (i = 0; i < PyList_Size(value); ++i)
        {
            PyObject* elem;
            PyObject* py_longName;
            PyObject* py_shortName;
            NSString* longName;
            NSString* shortName;
            const char* temp;

            elem = PyList_GetItem(value, i);

            if (elem == NULL || !PyList_Check(value) || PyList_Size(elem) != 2)
                continue;

            py_longName = PyList_GetItem(elem, 0);
            py_shortName = PyList_GetItem(elem, 1);

            /* should actually create a columnIdentifier object here, and init it with shortName
			   and longName. Missing is the class variable though... */
            if (py_longName == NULL || py_shortName == NULL ||
                !PyString_Check(py_longName) || !PyString_Check(py_shortName))
                continue;

            if ((temp = PyString_AsString(py_longName)) == NULL)
                continue;

            longName = [[NSString alloc] initWithUTF8String:temp];

            if ((temp = PyString_AsString(py_shortName)) == NULL)
            {
                [longName release];
                continue;
            }

            shortName = [[NSString alloc] initWithUTF8String:temp];

            column = [[ColumnIdentifier alloc] initWithPlugin:self
                                                        index:i
                                                     longName:longName
                                                    shortName:shortName];
            [ret addObject:column];
            [column release];
            [longName release];
            [shortName release];
        }
    }

    Py_XDECREF(args);
    Py_XDECREF(value);

    return [ret autorelease];
}

- (NSString*)columnStringForIndex:(unsigned int)fieldIndex data:(NSData*)data
{
    NSString* ret;
    PyObject* args;
    PyObject* value;
    const char* temp;

    ret = nil;
    args = NULL;
    value = NULL;

    if ((args = PyTuple_New(2)) == NULL)
        goto err;

    if ((value = PyLong_FromVoidPtr(data)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 0, value) != 0)
        goto err;

    if ((value = PyLong_FromUnsignedLong(fieldIndex)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 1, value) != 0)
        goto err;

    if ((value = PyObject_CallObject(columnStringForIndexFunc, args)) == NULL)
    {
        PyErr_Print();
        goto err;
    }

    if (PyString_Check(value))
    {
        if ((temp = PyString_AsString(value)) != NULL)
            ret = [[NSString alloc] initWithUTF8String:temp];
    }

err:
    Py_XDECREF(args);
    Py_XDECREF(value);

    return [ret autorelease];
}

- (NSComparisonResult)compareWith:(NSData*)comp_data
                          atIndex:(unsigned int)fieldIndex
                             data:(NSData*)data
{
    PyObject* args;
    PyObject* value;
    long temp;

    args = NULL;
    value = NULL;
    temp = 0;

    if ((args = PyTuple_New(3)) == NULL)
        goto err;

    if ((value = PyLong_FromVoidPtr(data)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 0, value) != 0)
        goto err;

    if ((value = PyLong_FromVoidPtr(comp_data)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 1, value) != 0)
        goto err;

    if ((value = PyLong_FromUnsignedLong(fieldIndex)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 2, value) != 0)
        goto err;

    if ((value = PyObject_CallObject(compareColumnForIndex, args)) == NULL)
    {
        PyErr_Print();
        goto err;
    }

    if (PyInt_Check(value))
    {
        /* can return -1 on failure, assume it always succeeds */
        temp = PyInt_AsLong(value);
    }

err:
    Py_XDECREF(args);
    Py_XDECREF(value);

    if (temp < 0)
        return NSOrderedAscending;
    if (temp > 0)
        return NSOrderedDescending;

    return NSOrderedSame;
}

- (OutlineViewItem*)outlineViewItemTreeForData:(NSData*)data
{
    OutlineViewItem* ret;
    PyObject* args;
    PyObject* value;

    ret = nil;
    args = NULL;
    value = NULL;

    if ((args = PyTuple_New(1)) == NULL)
        return nil;

    if ((value = PyLong_FromVoidPtr(data)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 0, value) != 0)
        goto err;

    if ((value = PyObject_CallObject(descriptionTreeFunc, args)) == NULL)
    {
        PyErr_Print();
        goto err;
    }

    ret = buildOutlineViewItemTreeFromList(value);

err:
    Py_XDECREF(args);
    Py_XDECREF(value);

    return ret;
}

- (BOOL)isValidData:(NSData*)data
{
    PyObject* args;
    PyObject* value;
    BOOL ret;

    ret = NO;
    args = NULL;
    value = NULL;

    if ((args = PyTuple_New(1)) == NULL)
        return NO;

    if ((value = PyLong_FromVoidPtr(data)) == NULL)
        goto err;

    /* value reference stolen here */
    if (PyTuple_SetItem(args, 0, value) != 0)
        goto err;

    if ((value = PyObject_CallObject(isValidDataFunc, args)) == NULL)
    {
        PyErr_Print();
        goto err;
    }

    if (PyBool_Check(value))
        ret = (value == Py_True) ? YES : NO;

err:
    Py_XDECREF(args);
    Py_XDECREF(value);

    return ret;
}

- (void)clear
{
    /* Py_XDECREF checks for NULL */
    Py_XDECREF(module);
    Py_XDECREF(shortNameFunc);
    Py_XDECREF(longNameFunc);
    Py_XDECREF(infoFunc);
    Py_XDECREF(descriptionTreeFunc);
    Py_XDECREF(isValidDataFunc);
    Py_XDECREF(columnIdentifiersFunc);
    Py_XDECREF(columnStringForIndexFunc);
    Py_XDECREF(compareColumnForIndex);
    module = NULL;
    shortNameFunc = NULL;
    longNameFunc = NULL;
    infoFunc = NULL;
    descriptionTreeFunc = NULL;
    isValidDataFunc = NULL;
    columnIdentifiersFunc = NULL;
    columnStringForIndexFunc = NULL;
    compareColumnForIndex = NULL;
}

- (void)dealloc
{
    [self clear];
    [super dealloc];
}

@end

static PyMODINIT_FUNC init_packetpeeper_module(void)
{
    void* Py_InitModule4TraceRefs(
        char* name, void* methods, char* doc, void* self, int apiver);
    Py_InitModule("packetpeeper", ppMethods);
}

static PyObject* pp_size(PyObject* self, PyObject* args)
{
    PyObject* py_data;
    NSData* data;

    if (!PyTuple_Check(args) || PyTuple_Size(args) != 1)
    {
        PyErr_SetString(PyExc_TypeError, "function takes one argument");
        return NULL;
    }

    if ((py_data = PyTuple_GetItem(args, 0)) == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }

    if ((data = PyLong_AsVoidPtr(py_data)) == nil)
    {
        PyErr_NoMemory();
        return NULL;
    }

    return Py_BuildValue("k", [data length]);
}

/*
unpack(fmt, string)
Unpack the string (presumably packed by pack(fmt, ...)) according to the given format.
The result is a tuple even if it contains exactly one item. The string must contain
exactly the amount of data required by the format (len(string) must equal calcsize(fmt)).

Before each format char there may be a repeat modifier (including zero)
and before that, a byte-order modifier.

    order   alignment
@	native	native
=	native	standard
<	little-endian	standard
>	big-endian	standard
!	network (= big-endian)	standard

x	pad byte	no value	
c	char	string of length 1	
b	signed char	integer	
B	unsigned char	integer	
h	short	integer	
H	unsigned short	integer	
i	int	integer	
I	unsigned int	long	
l	long	integer	
L	unsigned long	long	
q	long long	long	(1)
Q	unsigned long long	long	(1)
f	float	float	
d	double	float	
s	char[]	string

A	IPv4 address

Whitespace characters between formats are ignored; a count and its format must not contain whitespace though.

*/

static PyObject* pp_unpack(PyObject* self, PyObject* args)
{
    NSData* data;
    PyObject* py_format;
    PyObject* py_data;
    PyObject* results; /* list which we turn into tuple at end of processing */
    PyObject* tuple;   /* return value */
    const char* format;
    const void* pkt_data;
    size_t pkt_data_len;
    unsigned int i;
    enum data_type data_type;
    enum endian_modifier endian_modifier;
    unsigned int repeat_modifier;

    results = NULL;

    if (!PyTuple_Check(args) || PyTuple_Size(args) != 2)
    {
        PyErr_SetString(PyExc_TypeError, "function takes two arguments");
        goto err;
    }

    if ((py_data = PyTuple_GetItem(args, 0)) == NULL)
    {
        PyErr_NoMemory();
        goto err;
    }

    if ((data = PyLong_AsVoidPtr(py_data)) == nil)
    {
        PyErr_NoMemory();
        goto err;
    }

    if ((py_format = PyTuple_GetItem(args, 1)) == NULL)
    {
        PyErr_NoMemory();
        goto err;
    }

    if (!PyString_Check(py_format))
    {
        PyErr_SetString(PyExc_TypeError, "a string is required");
        goto err;
    }

    if ((format = PyString_AsString(py_format)) == NULL)
    {
        PyErr_NoMemory();
        goto err;
    }

    /* tuples are immutable, so create a list which we will later turn into a tuple */
    if ((results = PyList_New(0)) == NULL)
    {
        PyErr_NoMemory();
        goto err;
    }

    pkt_data = [data bytes];
    pkt_data_len = [data length];
    i = 0;

    while (format[i] != '\0')
    {
        PyObject* item;
        size_t nbytes_incr;

        i += strspn(&format[i], " \t\n\r");

        if (format[i] == '\0')
            break;

        i += pp_unpack_parse_endian_modifier(&format[i], &endian_modifier);
        i += pp_unpack_parse_repeat_modifier(&format[i], &repeat_modifier);
        i += pp_unpack_parse_type(&format[i], &data_type);

        if (data_type == TYPE_NONE)
        {
            PyErr_SetString(PyExc_TypeError, "invalid format string");
            goto err;
        }

        if (repeat_modifier == 0 && data_type != TYPE_STRING)
            continue;

        if (data_type == TYPE_STRING)
        {
            char* temp;

            if (repeat_modifier > pkt_data_len)
            {
                PyErr_SetString(
                    PyExc_TypeError,
                    "not enough data for format string (repeat modifier)");
                goto err;
            }

            /* PyString_FromFormat doesn't support the full set of
			   printf format strings, so we have to futz about here */

            if ((temp = malloc(repeat_modifier + 1)) == NULL)
            {
                PyErr_NoMemory();
                goto err;
            }

            snprintf(
                temp,
                repeat_modifier + 1,
                "%.*s",
                repeat_modifier,
                (char*)pkt_data);
            item = PyString_FromString(temp);

            free(temp);

            if (item == NULL)
                goto err;

            if (PyList_Append(results, item) == -1)
            {
                Py_DECREF(item);
                goto err;
            }

            Py_DECREF(item);

            pkt_data = (uint8_t*)pkt_data + repeat_modifier;
            pkt_data_len -= repeat_modifier;
        }
        else
        {
            while (repeat_modifier-- > 0)
            {
                item = NULL;
                nbytes_incr = 0;

                switch (data_type)
                {
                case TYPE_PAD_BYTE:
                    nbytes_incr = 1;
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (pad)");
                        goto err;
                    }
                    break;

                case TYPE_CHAR:
                    nbytes_incr = sizeof(char);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (char)");
                        goto err;
                    }
                    item = PyString_FromFormat("%c", *(char*)pkt_data);
                    break;

                case TYPE_INT8:
                    nbytes_incr = sizeof(int8_t);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (int8)");
                        goto err;
                    }
                    item = PyInt_FromLong(*(int8_t*)pkt_data);
                    break;

                case TYPE_UINT8:
                    nbytes_incr = sizeof(uint8_t);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (uint8)");
                        goto err;
                    }
                    item = PyInt_FromLong(*(uint8_t*)pkt_data);
                    break;

                case TYPE_INT16:
                    nbytes_incr = sizeof(int16_t);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (int16)");
                        goto err;
                    }
                    if (endian_modifier == BIG_ORDER_STD_ALIGN)
                        item = PyInt_FromLong(be16toh(*(int16_t*)pkt_data));
                    else if (endian_modifier == LITTLE_ORDER_STD_ALIGN)
                        item = PyInt_FromLong(le16toh(*(int16_t*)pkt_data));
                    else
                        item = PyInt_FromLong(*(int16_t*)pkt_data);
                    break;

                case TYPE_UINT16:
                    nbytes_incr = sizeof(uint16_t);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (uint16)");
                        goto err;
                    }
                    if (endian_modifier == BIG_ORDER_STD_ALIGN)
                        item = PyInt_FromLong(be16toh(*(uint16_t*)pkt_data));
                    else if (endian_modifier == LITTLE_ORDER_STD_ALIGN)
                        item = PyInt_FromLong(le16toh(*(uint16_t*)pkt_data));
                    else
                        item = PyInt_FromLong(*(uint16_t*)pkt_data);
                    break;

                case TYPE_INT32:
                    nbytes_incr = sizeof(int32_t);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (int32)");
                        goto err;
                    }
                    if (endian_modifier == BIG_ORDER_STD_ALIGN)
                        item = PyInt_FromLong(be32toh(*(int32_t*)pkt_data));
                    else if (endian_modifier == LITTLE_ORDER_STD_ALIGN)
                        item = PyInt_FromLong(le32toh(*(int32_t*)pkt_data));
                    else
                        item = PyInt_FromLong(*(int32_t*)pkt_data);
                    break;

                case TYPE_UINT32:
                    nbytes_incr = sizeof(uint32_t);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (uint32)");
                        goto err;
                    }
                    if (endian_modifier == BIG_ORDER_STD_ALIGN)
                        item = PyLong_FromUnsignedLong(
                            be32toh(*(uint32_t*)pkt_data));
                    else if (endian_modifier == LITTLE_ORDER_STD_ALIGN)
                        item = PyLong_FromUnsignedLong(
                            le32toh(*(uint32_t*)pkt_data));
                    else
                        item = PyLong_FromUnsignedLong(*(uint32_t*)pkt_data);
                    break;

                case TYPE_INT64:
                    nbytes_incr = sizeof(int64_t);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (int64)");
                        goto err;
                    }
                    if (endian_modifier == BIG_ORDER_STD_ALIGN)
                        item =
                            PyLong_FromLongLong(be64toh(*(int64_t*)pkt_data));
                    else if (endian_modifier == LITTLE_ORDER_STD_ALIGN)
                        item =
                            PyLong_FromLongLong(le64toh(*(int64_t*)pkt_data));
                    else
                        item = PyLong_FromLongLong(*(int64_t*)pkt_data);
                    break;

                case TYPE_UINT64:
                    nbytes_incr = sizeof(uint64_t);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (uint64)");
                        goto err;
                    }
                    if (endian_modifier == BIG_ORDER_STD_ALIGN)
                        item = PyLong_FromUnsignedLongLong(
                            be64toh(*(uint64_t*)pkt_data));
                    else if (endian_modifier == LITTLE_ORDER_STD_ALIGN)
                        item = PyLong_FromUnsignedLongLong(
                            le64toh(*(uint64_t*)pkt_data));
                    else
                        item =
                            PyLong_FromUnsignedLongLong(*(uint64_t*)pkt_data);
                    break;

                case TYPE_FLOAT:
                    nbytes_incr = sizeof(float);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (float)");
                        goto err;
                    }
                    item = PyFloat_FromDouble(*(float*)pkt_data);
                    break;

                case TYPE_DOUBLE:
                    nbytes_incr = sizeof(double);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (double)");
                        goto err;
                    }
                    item = PyFloat_FromDouble(*(double*)pkt_data);
                    break;

                case TYPE_IPv4_ADDR:
                    nbytes_incr = sizeof(struct in_addr);
                    if (nbytes_incr > pkt_data_len)
                    {
                        PyErr_SetString(
                            PyExc_TypeError,
                            "not enough data for format string (IPv4 address)");
                        goto err;
                    }
                    item = PyString_FromString([ipaddrstr(
                        pkt_data, sizeof(struct in_addr)) UTF8String]);
                    break;

                default
                    : /* this can never be reached, only really here to suppress compiler warnings */
                    PyErr_SetString(PyExc_TypeError, "invalid format string");
                    goto err;
                }
                if (item == NULL && data_type != TYPE_PAD_BYTE)
                {
                    PyErr_NoMemory();
                    goto err;
                }

                if (data_type != TYPE_PAD_BYTE)
                {
                    if (PyList_Append(results, item) == -1)
                    {
                        Py_DECREF(item);
                        PyErr_NoMemory();
                        goto err;
                    }
                    Py_DECREF(item);
                }

                pkt_data = (uint8_t*)pkt_data + nbytes_incr;
                pkt_data_len -= nbytes_incr;
            }
        }
    }

    tuple = PyList_AsTuple(results);
    Py_DECREF(results);
    results = NULL;

    if (tuple == NULL)
    {
        PyErr_NoMemory();
        goto err;
    }

    return tuple;

err:
    /* create exception */
    Py_XDECREF(results);
    return NULL;
}

static size_t pp_unpack_parse_endian_modifier(
    const char* format, enum endian_modifier* endian_modifier)
{
    switch (*format)
    {
    case '@':
        *endian_modifier = NATIVE_ORDER_NATIVE_ALIGN;
        return 1;

    case '=':
        *endian_modifier = NATIVE_ORDER_STD_ALIGN;
        return 1;

    case '<':
        *endian_modifier = LITTLE_ORDER_STD_ALIGN;
        return 1;

    case '>':
    case '!':
        *endian_modifier = BIG_ORDER_STD_ALIGN;
        return 1;
    }

    *endian_modifier = NATIVE_ORDER_NATIVE_ALIGN;
    return 0;
}

static size_t pp_unpack_parse_repeat_modifier(
    const char* format, unsigned int* repeat_modifier)
{
    long temp;
    char* endptr;

    errno = 0;
    temp = strtol(format, &endptr, 10);

    if (errno == EINVAL || temp < 0 || temp == LONG_MAX)
        *repeat_modifier = 1;
    else
        *repeat_modifier = (unsigned int)temp;

    return ((intptr_t)endptr - (intptr_t)format);
}

static size_t
pp_unpack_parse_type(const char* format, enum data_type* data_type)
{
    switch (*format)
    {
    case 'x':
        *data_type = TYPE_PAD_BYTE;
        return 1;

    case 'c':
        *data_type = TYPE_CHAR;
        return 1;

    case 's':
        *data_type = TYPE_STRING;
        return 1;

    case 'b':
        *data_type = TYPE_INT8;
        return 1;

    case 'B':
        *data_type = TYPE_UINT8;
        return 1;

    case 'h':
        *data_type = TYPE_INT16;
        return 1;

    case 'H':
        *data_type = TYPE_UINT16;
        return 1;

    case 'i':
    case 'l':
        *data_type = TYPE_INT32;
        return 1;

    case 'I':
    case 'L':
        *data_type = TYPE_UINT32;
        return 1;

    case 'q':
        *data_type = TYPE_INT64;
        return 1;

    case 'Q':
        *data_type = TYPE_UINT64;
        return 1;

    case 'f':
        *data_type = TYPE_FLOAT;
        return 1;

    case 'd':
        *data_type = TYPE_DOUBLE;
        return 1;

    case 'A':
        *data_type = TYPE_IPv4_ADDR;
        return 1;
    }

    *data_type = TYPE_NONE;
    return 0;
}

static OutlineViewItem* buildOutlineViewItemTreeFromList(PyObject* list)
{
    OutlineViewItem* outlineViewItem;
    PyObject* elem;
    unsigned int i;

    if (list == NULL || !PyList_Check(list))
        return nil;

    outlineViewItem = [[OutlineViewItem alloc] init];

    for (i = 0; i < PyList_Size(list); ++i)
    {
        elem = PyList_GetItem(list, i);

        if (PyString_Check(elem))
        {
            NSString* str;
            const char* temp;

            if ((temp = PyString_AsString(elem)) != NULL)
            {
                if ((str = [[NSString alloc] initWithUTF8String:temp]) != nil)
                {
                    [outlineViewItem addObject:str];
                    [str release];
                }
            }
        }
        else if (PyList_Check(elem))
        {
            OutlineViewItem* child;
            if ((child = buildOutlineViewItemTreeFromList(elem)) != nil)
                [outlineViewItem addChild:child];
        }
    }

    return [outlineViewItem autorelease];
}

static inline void swap(uint8_t* a, uint8_t* b)
{
    const uint8_t temp = *a;
    *a = *b;
    *b = temp;
}

static uint16_t bswap16(uint16_t int16)
{
    uint8_t* p;
    p = (uint8_t*)&int16;
    swap(&p[0], &p[1]);
    return int16;
}

static uint32_t bswap32(uint32_t int32)
{
    uint8_t* p;
    p = (uint8_t*)&int32;
    swap(&p[0], &p[3]);
    swap(&p[1], &p[2]);
    return int32;
}

static uint64_t bswap64(uint64_t int64)
{
    uint8_t* p;
    p = (uint8_t*)&int64;
    swap(&p[0], &p[7]);
    swap(&p[1], &p[6]);
    swap(&p[2], &p[5]);
    swap(&p[3], &p[4]);
    return int64;
}
