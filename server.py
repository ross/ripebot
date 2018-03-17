#!/usr/bin/env python

from logging import DEBUG as LOGGING_DEBUG, getLogger
from os import environ
from tornado.ioloop import IOLoop
from tornado.options import define, options, parse_command_line
from tornado.web import Application

from botie.backends.slack import SlackBackend
from botie.handlers.status import StatusHandler

from ripe.client import RipeClient
from ripebot.handlers import RipeHandler

define('debug', default=False, help='Enable debug mode')
define('address', default='0.0.0.0',
       help='Set the interface to listen on')
define('port', default=8888, help='Port to listen on')


if __name__ == '__main__':
    parse_command_line()

    ripe_client = RipeClient('RipeBot', environ['RIPE_API_KEY'])

    auth_tokens = environ['SLACK_AUTH_TOKENS'].split(',')
    app = Application([
        (r'/slack/ripe', RipeHandler, {
            'backend': SlackBackend(auth_tokens=auth_tokens),
            'ripe_client': ripe_client,
        }),
        (r'/_status', StatusHandler),
    ], debug=options.debug)
    if options.debug:
        getLogger().level = LOGGING_DEBUG
    app.listen(options.port, address=options.address)
    IOLoop.current().start()
