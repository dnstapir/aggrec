import logging

from fastapi import APIRouter, Request

from .db_models import AggregateMetadata
from .helpers import check_client_access
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
    "/api/v1/stats/creators",
    tags=["backend"],
)
def get_stats_creators(request: Request) -> CreatorsResponse:
    """Get statistics for all creators."""

    check_client_access(request, request.app.settings.http.stats_hosts)

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
