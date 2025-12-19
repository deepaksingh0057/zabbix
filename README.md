# Zabbix event tracker helper

A small Python helper to track Zabbix-style events locally. It keeps a JSON state file so you can see:

- Current/present alarms
- Acknowledged vs. unacknowledged alarms
- Resolved alarms
- Active vs. deleted hosts
- Whether hosts are SNMP-based or agent-based

## Quick start

```bash
python tracker.py --state state.json add-host core-router snmp
python tracker.py --state state.json add-host db-agent agent
python tracker.py --state state.json alarm core-router high "Interface Gi0/1 down"
python tracker.py --state state.json ack 1
python tracker.py --state state.json resolve 1
python tracker.py --state state.json summary
```

`--state` controls where the JSON state is stored (defaults to `state.json`).

## Commands

- `add-host <name> <snmp|agent>` — register a new host.
- `delete-host <name>` — mark a host as deleted while keeping its history.
- `alarm <host> <severity> <message>` — create a new alarm for a host.
- `ack <alarm_id>` — mark an alarm as acknowledged.
- `resolve <alarm_id>` — mark an alarm as resolved.
- `check-connection --server-url <url> [--api-token TOKEN | --user USER --password PASS]` — verify you can reach the Zabbix JSON-RPC API (and optionally log in).
- `summary` — show present alarms, acknowledged/unacknowledged breakdown, resolved alarms, and host inventory (including SNMP vs. agent and deleted hosts).

## Connecting to a Zabbix server

Use `check-connection` to confirm your Zabbix API URL and credentials work. The command talks to `api_jsonrpc.php`, fetches the API version, and, if you pass a token or username/password, performs an authenticated call to prove the credentials are valid.

```bash
# With a pre-issued API token
python tracker.py check-connection --server-url https://zabbix.example.com --api-token YOURTOKEN

# With username/password (the tool logs in to fetch a temporary token)
python tracker.py check-connection --server-url https://zabbix.example.com --user Admin --password 'zabbix'

# Custom timeout if your server is slow to respond (defaults to 10s)
python tracker.py check-connection --server-url https://zabbix.example.com --api-token YOURTOKEN --timeout 20
```

If you prefer environment variables, wrap the command (for example: `ZABBIX_URL=... ZABBIX_TOKEN=... python tracker.py check-connection --server-url "$ZABBIX_URL" --api-token "$ZABBIX_TOKEN"`).

## Example state file

`sample_state.json` contains example data that exercises all the report sections. You can view it with:

```bash
python tracker.py --state sample_state.json summary
```
