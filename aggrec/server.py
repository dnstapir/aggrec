import argparse
import logging

from waitress import serve

from .app import create_app


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Aggregate Receiver")

    parser.add_argument(
        "--config", dest="config", metavar="filename", help="Configuration file"
    )
    parser.add_argument(
        "--host", dest="host", help="Host address to bind to", default="0.0.0.0"
    )
    parser.add_argument("--port", dest="port", help="Port to listen on", default=8080)
    parser.add_argument(
        "--debug", dest="debug", action="store_true", help="Enable debugging"
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    app = create_app(args.config)

    serve(app, listen=f"{args.host}:{args.port}")


if __name__ == "__main__":
    main()
