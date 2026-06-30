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

## Docker / Compose

The image runs uvicorn on port `6008` and reads reports from `/data` inside the container.

`docker-compose.yml` bind-mounts the local `data/` directory as `/data:ro`, so drop your `*.md` reports and `connections.db` there (or change the volume mapping to a real host path).

> **Security:** the app has no auth. Bind to `127.0.0.1` (default) and put a reverse proxy with TLS + auth in front if you expose it beyond a trusted LAN.

```bash
# build & start in the background
docker compose up -d --build

# tail logs
docker compose logs -f

# stop
docker compose down
```

Customize the host port or data path by editing `docker-compose.yml`:

```yaml
ports:
  - "127.0.0.1:6008:6008"   # host:container
volumes:
  - /srv/tinyco/data:/data:ro   # absolute host path recommended
```

Or override at run time:

```bash
DATA_DIR=/srv/tinyco/data docker compose up -d
```
