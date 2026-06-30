# tinyco-admin-530

Personal admin dashboard for MikroTik / Proxmox health reports and firewall connection snapshots.

## Run

```bash
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

For LAN access, bind `0.0.0.0` and put a reverse proxy with auth/TLS in front if exposed beyond a trusted network.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `./data` | Directory containing `*-health-check-*.md` reports and `connections.db` |
| `CONNECTIONS_DB` | `$DATA_DIR/connections.db` | SQLite firewall snapshot database |

Expected report filenames:

- `mikrotik-health-check-*.md`
- `pve-health-check-*.md`

## Tests

```bash
pytest
```
