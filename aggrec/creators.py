import logging
from collections import defaultdict

from fastapi import APIRouter, Request

from .db_models import AggregateMetadata
from .models import CreatorInformation, CreatorsResponse

logger = logging.getLogger(__name__)


router = APIRouter()

GET_CREATORS_LAST_PIPELINE = [
    {
        "$sort": {
            "_id": -1,
        }
    },
    {
        "$group": {
            "_id": "$creator",
            "last_id": {"$first": "$_id"},
        }
    },
    {
        "$sort": {
            "_id": 1,
        }
    },
]

GET_CREATORS_COUNT_PIPELINE = [
    {
        "$group": {
            "_id": "$creator",
            "aggregates_count": {"$sum": 1},
            "aggregates_total_size": {"$sum": "$content_length"},
        }
    }
]


@router.get(
    "/api/v1/creators",
    tags=["backend"],
)
def get_creators(
    request: Request,
) -> CreatorsResponse:
    """Get a list of all creators."""

    count: dict[str, int] = defaultdict(int)
    total_size: dict[str, int] = defaultdict(int)

    for obj in AggregateMetadata.objects().aggregate(GET_CREATORS_COUNT_PIPELINE):
        creator = obj["_id"]
        count[creator] = obj["aggregates_count"]
        total_size[creator] = obj["aggregates_total_size"]

    creators = [
        CreatorInformation(
            creator=obj["_id"],
            last_aggregate_id=str(obj["last_id"]),
            last_seen=obj["last_id"].generation_time,
            aggregates_count=count[obj["_id"]],
            aggregates_total_size=total_size[obj["_id"]],
        )
        for obj in AggregateMetadata.objects().aggregate(GET_CREATORS_LAST_PIPELINE)
    ]

    return CreatorsResponse(creators=creators)
