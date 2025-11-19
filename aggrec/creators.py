import logging

from fastapi import APIRouter, Request

from .db_models import AggregateMetadata
from .models import CreatorInformation, CreatorsResponse

logger = logging.getLogger(__name__)


router = APIRouter()

# Pipeline to get creators with their aggregate statistics
GET_CREATORS_PIPELINE = [
    {
        "$sort": {"_id": -1},
    },
    {
        "$group": {
            "_id": "$creator",
            "last_id": {"$first": "$_id"},
            "aggregates_count": {"$sum": 1},
            "aggregates_total_size": {"$sum": "$content_length"},
        }
    },
    {
        "$sort": {"_id": 1},
    },
]


@router.get(
    "/api/v1/creators",
    tags=["backend"],
)
def get_creators(
    request: Request,
) -> CreatorsResponse:
    """Get a list of all creators."""

    creators = [
        CreatorInformation(
            creator=obj["_id"],
            last_aggregate_id=str(obj["last_id"]),
            last_seen=obj["last_id"].generation_time,
            aggregates_count=obj["aggregates_count"],
            aggregates_total_size=obj["aggregates_total_size"],
        )
        for obj in AggregateMetadata.objects().aggregate(GET_CREATORS_PIPELINE)
    ]

    return CreatorsResponse(creators=creators)
