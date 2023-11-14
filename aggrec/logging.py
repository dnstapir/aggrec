from datetime import datetime

from jsonformatter import JsonFormatter as _JsonFormatter

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


class JsonFormatter(_JsonFormatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created).astimezone()
        return dt.strftime(TIMESTAMP_FORMAT)
