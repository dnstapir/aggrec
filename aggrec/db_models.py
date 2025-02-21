from enum import StrEnum

from mongoengine import DateTimeField, DictField, Document, EnumField, IntField, StringField


class AggregateType(StrEnum):
    HISTOGRAM = "histogram"
    VECTOR = "vector"


class AggregateMetadata(Document):
    meta = {"collection": "aggregates"}

    creator = StringField()

    aggregate_type = EnumField(AggregateType)

    http_headers = DictField()

    content_type = StringField()
    content_length = IntField()
    content_digest = StringField(unique=True, sparse=True)

    s3_bucket = StringField()
    s3_object_key = StringField()

    aggregate_interval_start = DateTimeField()
    aggregate_interval_duration = IntField()
