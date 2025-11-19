import ipaddress
import logging

from fastapi import APIRouter, HTTPException, Request, status

from .db_models import AggregateMetadata
from .models import HealthcheckResult

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/api/v1/healthcheck",
    tags=["backend"],
)
async def healthcheck(
    request: Request,
) -> HealthcheckResult:
    """Perform health check with database and S3 access"""

    if request.client and request.client.host:
        try:
            client_address = ipaddress.ip_address(request.client.host)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid client IP address: {request.client.host}",
            ) from exc

        for address in request.app.settings.http.healthcheck_hosts:
            if client_address in address:
                break
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not my physician",
            )
    else:
        # Always allow health check if no client IP is provided
        pass

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
