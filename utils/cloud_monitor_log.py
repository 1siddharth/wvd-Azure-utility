import sys
import logging
import logging.handlers
import threading

def log_init(logger_name, log_file_name, maxbytes, backup_count):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
            '[%(asctime)s][%(name)s][%(levelname)s][%(threadName)s][%(filename)s:%(lineno)s]%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    log_handler = logging.handlers.RotatingFileHandler(filename=log_file_name, mode='a',
                                                       maxBytes=maxbytes, backupCount=backup_count)
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

    stream_log_handler = logging.StreamHandler(sys.stdout)
    stream_log_handler.setFormatter(formatter)
    logger.addHandler(stream_log_handler)

    logger.info('Log Initialization done')
    return logger


def extended_log_init(tenant_name, accountId, region, logger_name, functionality, log_file_name, maxbytes, backup_count):
    import os, os.path

    full_logger_name = logger_name + tenant_name + accountId + region + functionality
    logger = logging.getLogger(full_logger_name)
    log_file_name = log_file_name + '/' + tenant_name + '/' + accountId + '/' + region   
    fileName = log_file_name + '/' + functionality
    if not os.path.exists(log_file_name):
        os.makedirs(log_file_name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '[%(asctime)s][%(name)s][%(levelname)s][%(thread)d] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    log_handler = logging.handlers.RotatingFileHandler(filename=fileName, mode='a',
                                                       maxBytes=maxbytes, backupCount=backup_count)
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

    stream_log_handler = logging.StreamHandler(sys.stdout)
    stream_log_handler.setFormatter(formatter)
    logger.addHandler(stream_log_handler)

    logger.info('Log Initialization done')
    return logger

def getLogger(*args) :
    logger = logging.getLogger(*args)
    return logger

def info(*args) :
    currentThread = threading.current_thread()
    log = currentThread.log
    currentThread.logger =  getLogger(log)    
    try:
        currentThread.logger.info(*args)
    except:
        pass

def error(*args) :
    currentThread = threading.current_thread()
    log = currentThread.log
    currentThread.logger =  getLogger(log)    
    try:
        currentThread.logger.error(*args)
    except:
        pass

def warning(*args) :
    currentThread = threading.current_thread()
    log = currentThread.log
    currentThread.logger =  getLogger(log)    
    try:
        currentThread.logger.warning(*args)
    except:
        pass


