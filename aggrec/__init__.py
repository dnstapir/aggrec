from importlib.metadata import version

__version__ = version("aggrec")

try:
    from aggrec.buildinfo import __commit__, __timestamp__

    __verbose_version__ = f"{__version__} ({__commit__})"
except ModuleNotFoundError:
    __verbose_version__ = __version__
    __commit__ = None
    __timestamp__ = None
    pass


OPENAPI_METADATA = {
    "title": "DNS TAPIR Aggregate Receiver",
    "description": "The DNS TAPIR Aggregate Receiver is a server component used for submitting and retrieving TAPIR aggregates.",
    "version": __version__,
    "contact": {
        "name": "Jakob Schlyter",
        "email": "jakob@kirei.se",
    },
    "openapi_tags": [
        {"name": "client", "description": "Client operations"},
        {"name": "backend", "description": "Backend operations"},
    ],
}
