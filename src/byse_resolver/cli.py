"""Command-line interface: one resolved URL on stdout."""

import argparse
import sys

import requests

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(description="Resolve a Byse embed to its temporary HLS URL.")
    parser.add_argument("url", help="HTTPS embed URL: https://host/e/video-code[/title]")
    parser.add_argument("--referer", help="URL of the page containing the player")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    try:
        from .resolver import ByseResolver

        stream = ByseResolver().resolve(args.url, referer=args.referer)
        if stream is None:
            print("byse-resolver: no supported HLS stream found", file=sys.stderr)
            return 1
    except (ImportError, requests.RequestException, ValueError, KeyError, TypeError,
            OverflowError, TimeoutError) as error:
        print(f"byse-resolver: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("byse-resolver: interrupted", file=sys.stderr)
        return 130
    print(stream.url)
    return 0
