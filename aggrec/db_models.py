from enum import Enum

from mongoengine import DateTimeField, DictField, Document, EnumField, IntField, StringField


class AggregateType(Enum):
    HISTOGRAM = "histogram"
    VECTOR = "vector"


class AggregateMetadata(Document):
    meta = {"collection": "aggregates"}

    creator = StringField()

    aggregate_type = EnumField(AggregateType)

    http_headers = DictField()

    content_type = StringField()
    content_length = IntField()

    s3_bucket = StringField()
    s3_object_key = StringField()

    aggregate_interval_start = DateTimeField()
    aggregate_interval_duration = IntField()
