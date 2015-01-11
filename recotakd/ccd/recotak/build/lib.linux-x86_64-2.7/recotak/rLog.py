#!/usr/bin/env python2

import sys
import logging
import logging.handlers

#VERBOSITY_LEVELS = {
#    50: logging.CRITICAL,
#    40: logging.ERROR,
#    30: logging.WARNING,
#    20: logging.INFO,
#    10: logging.DEBUG,
#     0: logging.UNSET
#}

# the directory has to exist if ccd is running
# therefore omitting test for existance here
LOGFILE = '/var/log/ccd/plugins.log'
LOGLEVEL = logging.DEBUG
LOGLEVEL_FILE = logging.DEBUG
LOGLEVEL_CONSOLE = logging.WARNING
LOGNAME = 'PluginLogger'

MAX_VERBOSITY = 4


def _create_logger(name=LOGNAME):
    logger = logging.getLogger(name)
    logger.setLevel(LOGLEVEL)
    logger.addHandler(_create_rfilehandler())
    logger.file_handler_idx = len(logger.handlers) - 1
    logger.addHandler(_create_consolehandler())
    logger.console_handler_idx = len(logger.handlers) - 1
    return logger


def _create_rfilehandler(loglevel=LOGLEVEL_FILE, logfile=LOGFILE):
    # file rfile_handler, console_handlerannel that logs to file
    rfile_handler = logging.handlers.RotatingFileHandler(
        logfile,
        maxBytes=20000000,
        backupCount=5,
    )
    rfile_handler.setFormatter(logging.Formatter('<%(process)s, %(threadName)s, %(asctime)s> '
                                                 '%(name)s (%(funcName)s) [%(levelname)s] '
                                                 '%(message)s '))
    rfile_handler.setLevel(loglevel)
    return rfile_handler


def _create_consolehandler(loglevel=LOGLEVEL_CONSOLE):
    # stream rfile_handler, console_handlerannel that prints to console
    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setLevel(loglevel)
    console_handler.setFormatter(logging.Formatter('%(name)s [%(levelname)s] %(message)s'))
    return console_handler


log = _create_logger()


def get_level(verbosity=''):
    """
    get the log level according to verbosity string.
    loglevel is cut to valid values.
    Input:
        verbosity       e.g. 'v', 'vv', ... , 'vvvv'
    Output:
        loglevel        'v'        -> ERROR
                        'vv'       -> WARNING
                        'vvv'      -> INFO
                        'vvvv'     -> DEBUG
    """
    level = min(MAX_VERBOSITY, len(verbosity))
    if level > 4:
        level = 4
    if level > 0:
        level = (5 - level) * 10
    return level


def set_verbosity_file(verbosity=''):
    rfile_handler = _create_rfilehandler(loglevel=get_level(verbosity))
    log.handlers[log.file_handler_idx] = rfile_handler


def set_verbosity_console(verbosity=''):
    console_handler = _create_consolehandler(loglevel=get_level(verbosity))
    log.handlers[log.console_handler_idx] = console_handler


if __name__ == "__main__":
    print 'testing logger'
    for i in range(0, 7):
        verbosity = 'v' * i
        print '-' * 80
        print verbosity
        print '-' * 80
        set_verbosity_file(verbosity)
        set_verbosity_console(verbosity)
        log.debug('test verbosity: %s', verbosity)
        log.info('test verbosity: %s', verbosity)
        log.warning('test verbosity: %s', verbosity)
        log.error('test verbosity: %s', verbosity)
        log.critical('test verbosity: %s', verbosity)
