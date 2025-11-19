import logging

from fastapi import APIRouter, Request

from .db_models import AggregateMetadata
from .helpers import check_client_access
from .models import StatsAggregatesResponse, StatsCreatorInformation, StatsCreatorsResponse

logger = logging.getLogger(__name__)


router = APIRouter()

# Pipeline to get creators with their aggregate statistics
GET_STATS_CREATORS_PIPELINE = [
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

GET_STATS_AGGREGATES_PIPELINE = [
    {
        "$group": {
            "_id": "",
            "aggregates_count": {"$sum": 1},
            "aggregates_total_size": {"$sum": "$content_length"},
        }
    }
]


@router.get(
    "/api/v1/stats/creators",
    tags=["backend"],
)
def get_stats_creators(request: Request) -> StatsCreatorsResponse:
    """Get statistics for all creators."""

    check_client_access(request, request.app.settings.http.stats_hosts)

    creators = [
        StatsCreatorInformation(
            creator=obj["_id"],
            last_aggregate_id=str(obj["last_id"]),
            last_seen=obj["last_id"].generation_time,
            aggregates_count=obj["aggregates_count"],
            aggregates_total_size=obj["aggregates_total_size"],
        )
        for obj in AggregateMetadata.objects().aggregate(GET_STATS_CREATORS_PIPELINE)
    ]

    return StatsCreatorsResponse(creators=creators)


@router.get(
    "/api/v1/stats/aggregates",
    tags=["backend"],
)
def get_stats_aggregates(request: Request) -> StatsAggregatesResponse:
    """Get statistics for all aggregates."""

    check_client_access(request, request.app.settings.http.stats_hosts)

    objects = list(AggregateMetadata.objects().aggregate(GET_STATS_AGGREGATES_PIPELINE))

    if not objects:
        return StatsAggregatesResponse(
            aggregates_count=0,
            aggregates_total_size=0,
        )

    return StatsAggregatesResponse(
        aggregates_count=objects[0]["aggregates_count"],
        aggregates_total_size=objects[0]["aggregates_total_size"],
    )
