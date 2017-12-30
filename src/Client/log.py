import inspect
import logging
import sys


class ClientLogger:
    def __init__(self):
        logging.basicConfig(
            stream=sys.stdout,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ClientLogger')
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = True

    def log(self, level, message):
        func = inspect.currentframe().f_back.f_code

        self.logger.log(
            level, "%18s:%3i: %15s:  %s " % (
                func.co_filename.split("/")[-1],
                func.co_firstlineno,
                func.co_name,
                message,
            )
        )


logger = ClientLogger()
