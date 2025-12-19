from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


Timestamp = str


@dataclass
class Host:
    name: str
    type: str  # "snmp" or "agent"
    status: str = "active"  # "active" or "deleted"
    added_at: Timestamp = ""
    deleted_at: Optional[Timestamp] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class Alarm:
    id: int
    host: str
    severity: str
    message: str
    acknowledged: bool = False
    resolved: bool = False
    created_at: Timestamp = ""
    resolved_at: Optional[Timestamp] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class ZabbixTracker:
    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path
        self._state = self._load_state()

    def _load_state(self) -> Dict[str, object]:
        if self.state_path.exists():
            with self.state_path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        return {"hosts": [], "alarms": [], "next_alarm_id": 1}

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with self.state_path.open("w", encoding="utf-8") as handle:
            json.dump(self._state, handle, indent=2)

    def _now(self) -> str:
        return datetime.utcnow().isoformat(timespec="seconds") + "Z"

    def add_host(self, name: str, host_type: str) -> Host:
        if host_type not in {"snmp", "agent"}:
            raise ValueError("host_type must be 'snmp' or 'agent'")
        for host in self._state["hosts"]:
            if host["name"] == name and host["status"] == "active":
                raise ValueError(f"Host '{name}' already exists")
        host = Host(name=name, type=host_type, status="active", added_at=self._now())
        self._state["hosts"].append(host.to_dict())
        self._save_state()
        return host

    def delete_host(self, name: str) -> Host:
        for host in self._state["hosts"]:
            if host["name"] == name and host["status"] == "active":
                host["status"] = "deleted"
                host["deleted_at"] = self._now()
                self._save_state()
                return Host(**host)
        raise ValueError(f"Host '{name}' not found or already deleted")

    def _next_alarm_id(self) -> int:
        alarm_id = int(self._state.get("next_alarm_id", 1))
        self._state["next_alarm_id"] = alarm_id + 1
        return alarm_id

    def add_alarm(self, host: str, severity: str, message: str) -> Alarm:
        self._ensure_host_exists(host)
        alarm = Alarm(
            id=self._next_alarm_id(),
            host=host,
            severity=severity,
            message=message,
            acknowledged=False,
            resolved=False,
            created_at=self._now(),
        )
        self._state["alarms"].append(alarm.to_dict())
        self._save_state()
        return alarm

    def acknowledge_alarm(self, alarm_id: int) -> Alarm:
        alarm = self._get_alarm(alarm_id)
        alarm["acknowledged"] = True
        self._save_state()
        return Alarm(**alarm)

    def resolve_alarm(self, alarm_id: int) -> Alarm:
        alarm = self._get_alarm(alarm_id)
        alarm["resolved"] = True
        alarm["resolved_at"] = self._now()
        self._save_state()
        return Alarm(**alarm)

    def _get_alarm(self, alarm_id: int) -> Dict[str, object]:
        for alarm in self._state["alarms"]:
            if alarm["id"] == alarm_id:
                return alarm
        raise ValueError(f"Alarm {alarm_id} not found")

    def _ensure_host_exists(self, name: str) -> None:
        for host in self._state["hosts"]:
            if host["name"] == name and host["status"] == "active":
                return
        raise ValueError(f"Host '{name}' does not exist or is deleted")

    def summary(self) -> Dict[str, List[Dict[str, object]]]:
        alarms = [Alarm(**alarm) for alarm in self._state["alarms"]]
        hosts = [Host(**host) for host in self._state["hosts"]]

        present = [alarm for alarm in alarms if not alarm.resolved]
        acknowledged = [alarm for alarm in present if alarm.acknowledged]
        unacknowledged = [alarm for alarm in present if not alarm.acknowledged]
        resolved = [alarm for alarm in alarms if alarm.resolved]

        active_hosts = [host for host in hosts if host.status == "active"]
        deleted_hosts = [host for host in hosts if host.status == "deleted"]
        snmp_hosts = [host for host in active_hosts if host.type == "snmp"]
        agent_hosts = [host for host in active_hosts if host.type == "agent"]

        return {
            "present_alarms": [alarm.to_dict() for alarm in present],
            "acknowledged_alarms": [alarm.to_dict() for alarm in acknowledged],
            "unacknowledged_alarms": [alarm.to_dict() for alarm in unacknowledged],
            "resolved_alarms": [alarm.to_dict() for alarm in resolved],
            "active_hosts": [host.to_dict() for host in active_hosts],
            "deleted_hosts": [host.to_dict() for host in deleted_hosts],
            "snmp_hosts": [host.to_dict() for host in snmp_hosts],
            "agent_hosts": [host.to_dict() for host in agent_hosts],
        }

    def print_summary(self) -> None:
        report = self.summary()

        def section(title: str, items: List[Dict[str, object]], fields: List[str]) -> None:
            print(f"\n{title} ({len(items)}):")
            for item in items:
                rendered = ", ".join(f"{field}={item.get(field)}" for field in fields)
                print(f"  - {rendered}")

        section(
            "Present alarms",
            report["present_alarms"],
            ["id", "host", "severity", "message", "acknowledged", "created_at"],
        )
        section("Acknowledged", report["acknowledged_alarms"], ["id", "host", "message"])
        section(
            "Unacknowledged",
            report["unacknowledged_alarms"],
            ["id", "host", "message"],
        )
        section(
            "Resolved alarms",
            report["resolved_alarms"],
            ["id", "host", "message", "resolved_at"],
        )
        section("Active hosts", report["active_hosts"], ["name", "type", "added_at"])
        section("Deleted hosts", report["deleted_hosts"], ["name", "deleted_at"])
        section("SNMP hosts", report["snmp_hosts"], ["name", "added_at"])
        section("Agent hosts", report["agent_hosts"], ["name", "added_at"])


class ZabbixConnectionTester:
    def __init__(
        self,
        server_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self.server_url = self._normalize_url(server_url)
        self.username = username
        self.password = password
        self.token = token
        self.timeout = timeout

    def _normalize_url(self, url: str) -> str:
        if url.endswith("/api_jsonrpc.php"):
            return url
        return url.rstrip("/") + "/api_jsonrpc.php"

    def _rpc(self, method: str, params: Optional[Dict[str, object]] = None, auth: Optional[str] = None) -> object:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": 1,
        }
        if auth:
            payload["auth"] = auth

        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.server_url,
            data=data,
            headers={"Content-Type": "application/json-rpc"},
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:  # pragma: no cover - network handled at runtime
            raise ConnectionError(f"HTTP error contacting Zabbix API: {exc}") from exc
        except urllib.error.URLError as exc:  # pragma: no cover - network handled at runtime
            raise ConnectionError(f"Network error contacting Zabbix API: {exc.reason}") from exc

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:  # pragma: no cover - server response errors
            raise ConnectionError(f"Invalid JSON response from Zabbix API: {body}") from exc

        if "error" in parsed:
            error = parsed["error"]
            message = error.get("data") or error.get("message") or "Unknown error"
            raise ConnectionError(f"Zabbix API error for {method}: {message}")

        return parsed.get("result")

    def check(self) -> Dict[str, object]:
        version = self._rpc("apiinfo.version")

        auth_token: Optional[str] = self.token
        if not auth_token and self.username and self.password:
            auth_token = str(
                self._rpc(
                    "user.login",
                    {"user": self.username, "password": self.password},
                )
            )

        authenticated_version: Optional[object] = None
        if auth_token:
            authenticated_version = self._rpc("apiinfo.version", auth=auth_token)

        return {
            "version": version,
            "used_auth": bool(auth_token),
            "authenticated_version": authenticated_version,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Track Zabbix alarms and hosts locally.")
    parser.add_argument(
        "--state",
        default="state.json",
        type=Path,
        help="Path to the state file (JSON). Default: state.json",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    add_host_parser = subparsers.add_parser("add-host", help="Add a new host")
    add_host_parser.add_argument("name", help="Host name")
    add_host_parser.add_argument("type", choices=["snmp", "agent"], help="Host type")

    delete_host_parser = subparsers.add_parser("delete-host", help="Delete an existing host")
    delete_host_parser.add_argument("name", help="Host name")

    alarm_parser = subparsers.add_parser("alarm", help="Create a new alarm")
    alarm_parser.add_argument("host", help="Host name")
    alarm_parser.add_argument("severity", help="Alarm severity (text)")
    alarm_parser.add_argument("message", help="Alarm message")

    acknowledge_parser = subparsers.add_parser("ack", help="Acknowledge an alarm")
    acknowledge_parser.add_argument("alarm_id", type=int, help="Alarm ID")

    resolve_parser = subparsers.add_parser("resolve", help="Resolve an alarm")
    resolve_parser.add_argument("alarm_id", type=int, help="Alarm ID")

    connection_parser = subparsers.add_parser(
        "check-connection", help="Verify connectivity to a Zabbix server API"
    )
    connection_parser.add_argument("--server-url", required=True, help="Zabbix base URL")
    connection_parser.add_argument("--api-token", help="Existing Zabbix API token")
    connection_parser.add_argument("--user", help="Username (if logging in for a token)")
    connection_parser.add_argument("--password", help="Password (if logging in for a token)")
    connection_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10)",
    )

    subparsers.add_parser("summary", help="Print a summary report")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    tracker = ZabbixTracker(args.state)

    if args.command == "add-host":
        host = tracker.add_host(args.name, args.type)
        print(f"Added host {host.name} ({host.type})")
    elif args.command == "delete-host":
        host = tracker.delete_host(args.name)
        print(f"Deleted host {host.name}")
    elif args.command == "alarm":
        alarm = tracker.add_alarm(args.host, args.severity, args.message)
        print(f"Created alarm {alarm.id} for {alarm.host}")
    elif args.command == "ack":
        alarm = tracker.acknowledge_alarm(args.alarm_id)
        print(f"Acknowledged alarm {alarm.id}")
    elif args.command == "resolve":
        alarm = tracker.resolve_alarm(args.alarm_id)
        print(f"Resolved alarm {alarm.id}")
    elif args.command == "check-connection":
        tester = ZabbixConnectionTester(
            server_url=args.server_url,
            username=args.user,
            password=args.password,
            token=args.api_token,
            timeout=args.timeout,
        )
        result = tester.check()
        print(f"Connected to Zabbix API at {tester.server_url}")
        print(f"API version: {result['version']}")
        if result["used_auth"]:
            print("Authentication successful; verified API call with credentials/token.")
        else:
            print("No authentication provided; server reachable without login.")
    elif args.command == "summary":
        tracker.print_summary()


if __name__ == "__main__":
    main()
