#!/bin/bash

from __future__ import print_function

import swampyer

import time
import sys
import logging
import signal

logging.basicConfig(stream=sys.stdout, level=1)

try:
    server = swampyer.WAMPServer(
                    url='ws://0.0.0.0:8383/ws',
                    # cert
                    # key
                    # ver
                    uri_base="com.example.wamp.api",
                    realm='realm1',
                )

    def hello_world(*args, **kwargs):
        print("Received Args:{} Kwargs:{}".format(args,kwargs))
        return "Hello there!"

    server.register(
        "hello",
        hello_world,
    )

    def close_sig_handler(signal, frame):
        server.close()
        sys.exit()

    signal.signal(signal.SIGINT, close_sig_handler)

    server.start()
    time.sleep(60)


except swampyer.SwampyException as ex:
    print("Whoops, something went wrong: {}".format(ex))


