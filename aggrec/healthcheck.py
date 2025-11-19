import logging

from fastapi import APIRouter, HTTPException, Request, status

from .db_models import AggregateMetadata
from .helpers import check_client_access
from .models import HealthcheckResult

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/api/v1/healthcheck",
    tags=["backend"],
)
async def healthcheck(request: Request) -> HealthcheckResult:
    """Perform health check with database and S3 access"""

    check_client_access(request, request.app.settings.http.healthcheck_hosts)

    try:
        aggregates_count = AggregateMetadata.objects().count()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to connect to MongoDB",
        ) from exc

    try:
        s3_bucket = request.app.settings.s3.get_bucket_name()
        async with request.app.get_s3_client() as s3_client:
            _ = await s3_client.head_bucket(Bucket=s3_bucket)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to connect to S3",
        ) from exc

    return HealthcheckResult(
        status="OK",
        aggregates_count=aggregates_count,
    )
