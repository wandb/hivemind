"""Private executable for one read-only review certificate preparation."""

from __future__ import annotations

import argparse
import os
import sys
from contextlib import suppress
from typing import Any

from . import __version__
from .hivemind import HiveMindClient
from .review_worker import (
    PREPARATION_WORKER_PROTOCOL,
    decode_worker_request,
    encode_worker_response,
)


def _response(*, nonce: str, status: str, **values: Any) -> dict[str, Any]:
    return {
        "protocol": PREPARATION_WORKER_PROTOCOL,
        "importer_version": __version__,
        "nonce": nonce,
        "status": status,
        **values,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--result-fd", type=int, required=True)
    args = parser.parse_args(argv)
    if args.result_fd < 3:
        return 2
    try:
        request = sys.stdin.buffer.read()
        nonce, project, binary, session = decode_worker_request(request)

        # Import the preparation implementation only after the request has
        # passed the content-free private protocol boundary.
        from .errors import ATIFSchemaError, ReviewMirrorError
        from .review import _certificate_payload, _preseal_preparation_failure_code
        from .review import _prepare_session_stable as prepare_session_stable
        from .review_manifest import ReviewManifestError
        from .review_sink import HostedReviewError, preflight_review_runtime

        try:
            runtime = preflight_review_runtime()
            client = HiveMindClient(binary=binary)
            client.preflight()
            prepared = prepare_session_stable(
                client,
                session,
                project=project,
                runtime=runtime,
            )
            certificates = _certificate_payload(
                project=project,
                prepared=prepared,
                include_index_evidence=True,
            )
            response = _response(
                nonce=nonce,
                status="prepared",
                project=project,
                session={
                    "id": prepared.session.id,
                    "started_at": prepared.session.started_at,
                    "last_activity_at": prepared.session.last_activity_at,
                    "is_subagent": bool(prepared.session.parent_session_id),
                },
                certificates=certificates,
            )
        except (
            ATIFSchemaError,
            HostedReviewError,
            ReviewManifestError,
            ReviewMirrorError,
            ValueError,
        ) as error:
            error_code = _preseal_preparation_failure_code(error)
            if error_code is None:
                return 3
            response = _response(
                nonce=nonce,
                status="rejected",
                error_code=error_code,
            )
        encoded = encode_worker_response(response)
        while encoded:
            written = os.write(args.result_fd, encoded)
            encoded = encoded[written:]
        return 0
    except Exception:
        # The parent never receives an exception body: source/API/library
        # diagnostics may contain private transcript fragments.
        return 4
    finally:
        with suppress(OSError):
            os.close(args.result_fd)


if __name__ == "__main__":
    raise SystemExit(main())
