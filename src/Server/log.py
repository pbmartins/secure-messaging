import inspect
import logging

def log(level, message):
    func = inspect.currentframe().f_back.f_code
    logging.log(level, "%18s:%3i: %15s:  %s " % (
                func.co_filename.split("/")[-1],
                func.co_firstlineno,
                func.co_name,
                message,))

