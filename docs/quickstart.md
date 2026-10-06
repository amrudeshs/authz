# Quickstart

A five-minute walkthrough: start the example, then watch authorization allow
and deny as the role changes.

## Run it

```sh
cd example
docker compose up --build
```

This starts Postgres (applying the reference schema, the seed function and
the demo data) and the API on `http://localhost:8080`. The demo is seeded with
two workspaces (`acme`, `globex`) and four bearer tokens:

| Token | User | Workspace | Role |
|---|---|---|---|
| `owner-acme` | owner@acme.test | acme | owner (wildcard) |
| `editor-acme` | editor@acme.test | acme | editor |
| `member-acme` | member@acme.test | acme | member |
| `owner-globex` | owner@globex.test | globex | owner (wildcard) |

Requests carry `Authorization: Bearer <token>` and `X-Workspace: <slug>`.

## Watch allow / deny

```sh
B="http://localhost:8080"
H='-H "Content-Type: application/json"'

# public — no auth
curl -s $B/health

# 401 — no session
curl -si $B/projects | head -1

# 404 — the globex owner is not a member of acme (existence hiding)
curl -si -H 'X-Workspace: acme' -H 'Authorization: Bearer owner-globex' $B/projects | head -1

# 200 — the member may read
curl -s -H 'X-Workspace: acme' -H 'Authorization: Bearer member-acme' $B/projects

# 403 — the member may not write
curl -si -X POST -H 'Content-Type: application/json' \
  -H 'X-Workspace: acme' -H 'Authorization: Bearer member-acme' \
  -d '{"name":"Nope"}' $B/projects | head -1

# 201 — the editor may write
curl -si -X POST -H 'Content-Type: application/json' \
  -H 'X-Workspace: acme' -H 'Authorization: Bearer editor-acme' \
  -d '{"name":"Editor project"}' $B/projects | head -1

# 403 — deleteProject is owner-only; the editor is refused
curl -si -X DELETE -H 'X-Workspace: acme' -H 'Authorization: Bearer editor-acme' $B/projects/1 | head -1

# 200 — the wildcard owner may delete
curl -si -X DELETE -H 'X-Workspace: acme' -H 'Authorization: Bearer owner-acme' $B/projects/1 | head -1
```

## Role lifecycle + cache invalidation

Grant a brand-new capability to a member and watch it take effect on the next
request — no restart, no reseed.

```sh
# create a custom role
curl -s -X POST -H 'Content-Type: application/json' \
  -H 'X-Workspace: acme' -H 'Authorization: Bearer owner-acme' \
  -d '{"slug":"manager","name":"Manager"}' $B/roles

# grant it createProject
curl -s -X POST -H 'Content-Type: application/json' \
  -H 'X-Workspace: acme' -H 'Authorization: Bearer owner-acme' \
  -d '{"codename":"createProject","allow":true}' $B/roles/manager/permissions

# assign it to the member (user id 3)
curl -s -X POST -H 'X-Workspace: acme' -H 'Authorization: Bearer owner-acme' \
  $B/members/3/roles/manager

# 201 — the member now holds the capability (the cache was invalidated)
curl -si -X POST -H 'Content-Type: application/json' \
  -H 'X-Workspace: acme' -H 'Authorization: Bearer member-acme' \
  -d '{"name":"After grant"}' $B/projects | head -1

# 200 — revoke the binding; the member's cache entry is dropped
curl -si -X DELETE -H 'X-Workspace: acme' -H 'Authorization: Bearer owner-acme' \
  $B/members/3/roles/manager | head -1

# 403 — the capability is gone on the next request
curl -si -X POST -H 'Content-Type: application/json' \
  -H 'X-Workspace: acme' -H 'Authorization: Bearer member-acme' \
  -d '{"name":"After revoke"}' $B/projects | head -1
```

A grant to a **system** role is refused (403):

```sh
curl -si -X POST -H 'Content-Type: application/json' \
  -H 'X-Workspace: acme' -H 'Authorization: Bearer owner-acme' \
  -d '{"codename":"deleteProject","allow":true}' $B/roles/editor/permissions | head -1
```

## Tear down

```sh
docker compose down -v
```

## Run against a database already (no Docker)

The example also runs without Docker against any Postgres you point it at:

```sh
export DATABASE_URL='postgres://user:pass@localhost:5432/db'
go run ./example
```

With `DATABASE_URL` unset it serves the same demo dataset from memory, which
is how the unit tests run. The Postgres integration tests use the same
variable and are described in the README.
