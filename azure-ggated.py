#!/usr/bin/env python
#
# Copyright (c) 2015 Marcel Moolenaar
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import argparse
import azure
import azure.storage
import ctypes
import errno
import logging
import os
import sys
import threading
import Queue
import SocketServer


GH_CMD_READ = 0
GH_CMD_WRITE = 1
GH_CMD_STOP = 127
gh_cmd_names = ['RD', 'WR']

SECTOR_SIZE = 512
MAX_IO_SIZE = 4 * 1024 * 1024


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class ggate_version(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [('gv_magic', ctypes.c_char * 16),
                ('gv_version', ctypes.c_uint16),
                ('gv_error', ctypes.c_uint16)]


class ggate_cinit(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [('gc_path', ctypes.c_char * 1025),
                ('gc_flags', ctypes.c_uint64),
                ('gc_nconn', ctypes.c_uint16),
                ('gc_token', ctypes.c_uint32)]


class ggate_sinit(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [('gs_flags', ctypes.c_uint8),
                ('gs_mediasize', ctypes.c_uint64),
                ('gs_sectorsize', ctypes.c_uint32),
                ('gs_error', ctypes.c_uint16)]


class ggate_header(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [('gh_cmd', ctypes.c_uint8),
                ('gh_offset', ctypes.c_uint64),
                ('gh_length', ctypes.c_uint32),
                ('gh_seq', ctypes.c_uint64),
                ('gh_error', ctypes.c_uint16)]


default_account = os.getenv('AZURE_STORAGE_ACCOUNT')
default_key = os.getenv('AZURE_STORAGE_KEY')

logging.basicConfig(level=logging.INFO)

ap = argparse.ArgumentParser(description="ggate compatible Azure daemon")
ap.add_argument('--account', dest='account', default=default_account,
                help='storage account name')
ap.add_argument('--key', dest='key', default=default_key,
                help='storage account access key')
ap.add_argument('--threads', dest='threads', type=int, default=4,
                help='the number of concurrent requests [1..64]')

args = ap.parse_args()
if not args.account or not args.key:
    logging.error('Missing --account and/or --key information')
    sys.exit(1)

if args.threads < 1 or args.threads > 64:
    logging.error('%s is not a valid thread argument' % (args.threads))
    sys.exit(1)

bs = azure.storage.BlobService(account_name=args.account, account_key=args.key)

connections = {}
done = False
requests = Queue.Queue()
replies = Queue.Queue()


class ggate_handler(SocketServer.BaseRequestHandler):

    def recv(self, pkt):
        length = ctypes.sizeof(pkt)
        data = self.request.recv(length)
        if len(data) != length:
            return None
        cstring = ctypes.create_string_buffer(data)
        result = ctypes.cast(ctypes.pointer(cstring),
                             ctypes.POINTER(pkt)).contents
        return result

    def send(self, pkt):
        buf = ctypes.string_at(ctypes.byref(pkt), ctypes.sizeof(pkt))
        self.request.sendall(buf)

    def handle_requests(self, rqs, rsps, container, blobname, blob):
        global done
        while not done:
            hdr = self.recv(ggate_header)
            if not hdr:
                hdr = ggate_header(GH_CMD_STOP, 0, 0, 0, 0)
                rsps.put((hdr, None))
                return
            logging.info("REQ(%s): cmd=%s, offset=%s, length=%s" %
                         (hdr.gh_seq, hdr.gh_cmd, hdr.gh_offset,
                          hdr.gh_length))
            if hdr.gh_cmd not in [GH_CMD_READ, GH_CMD_WRITE]:
                hdr.gh_error = errno.EINVAL
                rsps.put((hdr, None))
                continue
            if hdr.gh_offset % SECTOR_SIZE or hdr.gh_length % SECTOR_SIZE:
                hdr.gh_error = errno.ESPIPE
                rsps.put((hdr, None))
                continue
            if hdr.gh_length > MAX_IO_SIZE:
                hdr.gh_error = errno.EFBIG
                rsps.put((hdr, None))
                continue
            if hdr.gh_offset + hdr.gh_length > blob.properties.content_length:
                hdr.gh_error = errno.ENOSPC
                rsps.put((hdr, None))
                continue
            if hdr.gh_cmd == GH_CMD_WRITE:
                buffer = ''
                length = hdr.gh_length
                while length > 0:
                    data = self.request.recv(length)
                    buffer += data
                    length -= len(data)
            else:
                buffer = None
            rqs.put((container, blobname, hdr, buffer))

    def handle_replies(self, queue):
        while not done:
            try:
                (hdr, data) = queue.get(timeout=1)
            except Queue.Empty:
                continue
            if hdr.gh_cmd == GH_CMD_STOP:
                queue.task_done()
                return
            logging.info("RSP(%s): error=%s" % (hdr.gh_seq, hdr.gh_error))
            self.send(hdr)
            if hdr.gh_cmd == GH_CMD_READ and hdr.gh_error == 0:
                self.request.sendall(data)
            queue.task_done()

    def handle(self):
        version = self.recv(ggate_version)
        if not version:
            logging.debug("error: expected version packet")
            return
        if version.gv_magic != "GEOM_GATE       ":
            logging.debug("error: wrong magic")
            return
        if version.gv_version != 0:
            logging.debug("error: wrong version")
            return
        # Just echo the version packet back
        self.send(version)

        # We better send errors back to the client from now on...

        cinit = self.recv(ggate_cinit)
        if not cinit:
            logging.debug("error: expected cinit packet")
            self.send(ggate_sinit(0, 0, 0, errno.EINVAL))
            return

        if cinit.gc_flags == 4:
            if cinit.gc_token in connections:
                logging.debug("error: token %x in use" % (cinit.gc_token))
                self.send(ggate_sinit(0, 0, 0, errno.EBUSY))
                return
            elts = cinit.gc_path.split('/')
            if len(elts) != 2:
                logging.info("error: path doesn't match '<container>/<blob>'")
                self.send(ggate_sinit(0, 0, 0, errno.EINVAL))
                return
            container = elts[0]
            blobname = elts[1]
            logging.info("looking for %s in %s" % (blobname, container))
            bloblist = bs.list_blobs(container, blobname)
            if len(bloblist) != 1:
                logging.info("error: no (unique) match for %s (got %d)" %
                             (blobname, len(bloblist)))
                self.send(ggate_sinit(0, 0, 0, errno.ENOENT))
                return
            blob = bloblist[0]
            connections[cinit.gc_token] = (container, blobname, blob)
            self.send(ggate_sinit(0, blob.properties.content_length,
                                  SECTOR_SIZE, 0))
            self.handle_replies(replies)
            del connections[cinit.gc_token]
            return

        if cinit.gc_flags == 8:
            if cinit.gc_token not in connections:
                logging.debug("error: token %x not in use" % (cinit.gc_token))
                self.send(ggate_sinit(0, 0, 0, errno.EINVAL))
                return
            (container, blobname, blob) = connections[cinit.gc_token]
            self.send(ggate_sinit(0, blob.properties.content_length,
                                  SECTOR_SIZE, 0))
            self.handle_requests(requests, replies, container, blobname, blob)
            return

        self.send(ggate_sinit(0, 0, 0, errno.EINVAL))
        logging.debug("error: invalid flags: %" % (cinit.gc_flags))


def azure_worker():
    while not done:
        try:
            (container, blobname, hdr, data) = requests.get(timeout=2)
        except Queue.Empty:
            continue
        limit = hdr.gh_offset + hdr.gh_length - 1
        range = 'bytes=%s-%s' % (hdr.gh_offset, limit)
        logging.info("%s: %s(%s): %s" % (blobname, gh_cmd_names[hdr.gh_cmd],
                                         hdr.gh_seq, range))
        try:
            if hdr.gh_cmd == GH_CMD_WRITE:
                bs.put_page(container, blobname, data, x_ms_range=range,
                            x_ms_page_write="update")
                data = None
            else:
                data = bs.get_blob(container, blobname, x_ms_range=range)
        except Exception:
            hdr.gh_error = errno.EIO
            data = None
        replies.put((hdr, data))
        requests.task_done()


for i in xrange(8):
    thr = threading.Thread(target=azure_worker)
    thr.setDaemon(True)
    thr.start()

s = ThreadedTCPServer(('', 3080), ggate_handler)
try:
    s.serve_forever()
except Exception as e:
    pass
done = True
s.shutdown()
s.server_close()
