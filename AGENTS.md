# Agent rules — apme-lib-core

Owner: `apostille-me`
Tracking: `DEN-3321`

This repository is the canonical Apostille Me persistence boundary. Keep public
wire contracts in `apostille-me/apme-interfaces`; keep desired SQL, persistence schema,
ORM generation, named database operations, and DPM inputs here.

Use focused feature branches and reviewed pull requests. Never add startup
migration behavior, raw database-handle exports, credentials, or customer data.
Resolve conflicts semantically after reading both histories. The fleet-wide
instructions are in `~/codes/AGENTS.md` and must be followed.
