from __future__ import annotations

import argparse
import logging
import sys

from vgen.cli.auth import login_session
from vgen.cli.client import GatewayClient, VgenClientError
from vgen.cli.identity_store import DeviceIdentityStore
from vgen.cli.profile import ProfileStore
from vgen.cli.session_store import SessionStore
from vgen.crypto import sign_http_request

from .daemon import BrokerDaemon, BrokerDaemonConfig
from .journal import BrokerJournal
from .rekey import BrokerRekeyHandler


def _client(profile_name: str | None) -> GatewayClient:
    profile = ProfileStore().get(profile_name)
    identity = DeviceIdentityStore().load(profile.key_ref or "default")
    session = SessionStore().load(profile.name)
    if session is None:
        # A Home Broker is expected to survive the 15-minute session lifetime
        # unattended.  Its certified device key can safely obtain a fresh,
        # key-bound session without a bearer token on disk or user input.
        session = login_session(profile, identity)

    def signer(method: str, path: str, body: bytes) -> dict[str, str]:
        return sign_http_request(
            identity.device_keys, method=method, path=path, body=body
        ).to_headers()

    return GatewayClient(
        profile,
        session_token=session.token,
        signer=signer,
        token_refresher=lambda: login_session(profile, identity).token,
    )


def run_broker(args: argparse.Namespace) -> int:
    client = _client(getattr(args, "profile", None))
    journal = BrokerJournal()
    daemon = BrokerDaemon(
        BrokerDaemonConfig(
            broker_id=args.broker_id,
            device_id=args.broker_device_id,
            poll_seconds=args.poll_seconds,
        ),
        client,
        journal=journal,
        command_handler=BrokerRekeyHandler(client, journal),
    )
    try:
        daemon.run(once=args.once)
        return 0
    finally:
        journal.close()
        client.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vgen-broker")
    parser.add_argument("serve", nargs="?")
    parser.add_argument("--broker-id", required=True)
    parser.add_argument("--broker-device-id", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--once", action="store_true")
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    try:
        raise SystemExit(run_broker(build_parser().parse_args()))
    except VgenClientError as exc:
        print(f"{exc.code} {exc.name}: {exc}", file=sys.stderr)
        raise SystemExit(exc.exit_code) from None
    except ValueError as exc:
        print(f"vgen-broker: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
