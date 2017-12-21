#!/usr/bin/env python2.7
# -*- coding: utf8 -*-
import logging
import os

import time

__author__ = 'Viktor Winkelmann'

import argparse
from core.Dispatcher import Dispatcher

VERSION = "1.0"

parser = argparse.ArgumentParser(description='Extract files from a pcap-file.')
parser.add_argument('input', metavar='PCAP_FILE', help='the input file')
parser.add_argument('output', metavar='OUTPUT_FOLDER', help='the target folder for extraction',
                    nargs='?', default='output')
parser.add_argument("-e", dest='entropy', help="use entropy based rawdata extraction",
                    action="store_true", default=False)
parser.add_argument("-wfd", dest='write_file_data', help="write the file to output folder",
                    action="store_true", default=False)
parser.add_argument("-nv", dest='verifyChecksums', help="disable IP/TCP/UDP checksum verification",
                    action="store_false", default=False)
parser.add_argument("--T", dest='udpTimeout', help="set timeout for UDP-stream heuristics",
                    type=int, default=120)


print 'pcapfex - Packet Capture Forensic Evidence Extractor - version %s' % (VERSION,)
print '----------=------===-----=--------=---------=------------------' + '-'*len(VERSION) + '\n'
args = parser.parse_args()

if not args.verifyChecksums:
    print 'Packet checksum verification disabled.'
if args.entropy:
    print 'Using entropy and statistical analysis for raw extraction and classification of unknown data.'


def get_logger():
    logger = logging.getLogger('PCAPFEX')
    logger.setLevel(logging.DEBUG)
    # create file handler which logs even debug messages
    fh = logging.FileHandler('pcapfex.log')
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    # add the handlers to logger
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


logger = get_logger()

# dispatcher = Dispatcher(logger, args.input, args.output, args.entropy, args.write_file_data,
#                         verifyChecksums=args.verifyChecksums,
#                         udpTimeout=args.udpTimeout,
#                         )
# dispatcher.run()

while True:
    path = 'F:\\Users\\hair\\Desktop\\Lucy\\pcaps - Copy'
    fullpath = ''
    for f in os.listdir(path):
        try:
            if f.startswith('s1m'):
                fullpath = os.path.join(path, f)
                logger.info(fullpath)
                dispatcher = Dispatcher(logger, fullpath, args.output, args.entropy, args.write_file_data,
                                        verifyChecksums=args.verifyChecksums,
                                        udpTimeout=args.udpTimeout,
                                        )
                dispatcher.run()
                os.remove(fullpath)
        except Exception as e:
            logger.exception(e)
            os.remove(fullpath)
    time.sleep(3)
