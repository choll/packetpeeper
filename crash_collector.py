#!/usr/bin/python

import cgi
import cgitb
import os
import uuid

DEST_FILE_PREFIX = "/home/packetpe/breakpad_minidumps/crash_%s" % uuid.uuid4()
cgitb.enable()

os.umask(0377)

text_fd = os.fdopen(os.open(DEST_FILE_PREFIX + ".txt", os.O_WRONLY|os.O_CREAT|os.O_EXCL), "w")
text_fd.write("OK\n")

form = cgi.FieldStorage()
for name in form:
    symbol = form[name]
    text_fd.write("%s=%s\n" % (name, symbol.type))

    if (symbol.type == "text/plain"):
        text_fd.write("%s=%s\n" % (name, symbol.value))
    elif (symbol.type == "application/octet-stream"):
        if (name == "upload_file_minidump"):
            dump_fd = os.fdopen(os.open(DEST_FILE_PREFIX + ".minidump", os.O_WRONLY|os.O_CREAT|os.O_EXCL), "w")
            dump_fd.write(symbol.file.read())

