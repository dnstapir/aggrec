from enum import Enum

from mongoengine import DictField, Document, EnumField, IntField, StringField


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
