# SentinelX privileged broker — prototype / no deployment

Status: **tested prototype**, not installed and not ready for privilege cutover.

The standalone implementation in security/privileged_broker.py is a proof of an
OS-owned admission boundary on Linux. It is separate from the application-level
sudo=true gate in the fork's PR #1. The broker has no route from the installed
SentinelX agent yet, and the service's historical sudo policy is unmodified.

## Threat model and operating scope

This prototype is deliberately bound to **codex-dev** and the existing
sentinelx identity UID 992 / GID 990. It is not a portable broker. A root
daemon listens on a Unix stream socket in a trusted root-owned directory
(0750, group sentinelx), exposing only two allowlisted fixed operations:

| Operation | Trusted effect |
| --- | --- |
| audit-check | Execute /usr/local/sbin/tohy-sentinelx-governed-admin audit-check |
| audit-record | Execute /usr/local/sbin/tohy-sentinelx-governed-admin audit-record |

The root-owned executable must have exact mode 0755; the broker launches it
without a shell, argv interpolation, caller environment, cwd or path supplied by
the request. Responses do not return the privileged subprocess output.

No other command, executable, path, service or user is configurable through
the client protocol. The root-only server code and its installation are
**not** a substitute for reviewing the two pre-existing operation handlers.

## Local protocol and one-use tickets

Socket protocol: one UTF-8 JSON object followed by a newline, maximum 4096
bytes. Each client is identified using Linux SO_PEERCRED. Schema version is
integer 1; all allowed request fields must match exactly.

Only a root peer may **issue**:

    {"version":1,"action":"issue","operation":"audit-check","target_uid":992,"target_gid":990,"ttl_seconds":60}

The response returns a random 256-bit bearer ticket. This is a secret: do not
log, forward, save or put a real ticket on the command line in production.
The broker stores only the SHA-256 digest of its bytes in a 0600 root-owned
SQLite database, binding operation, UID/GID, boot ID, issuance and expiry.
Ticket lifetime is 1–300 seconds.

Only peer UID 992/GID 990 may **execute**:

    {"version":1,"action":"execute","operation":"audit-check","ticket":"<secret>"}

The socket is root-owned and group sentinelx, mode 0660; ticket issuance
is additionally verified by peer UID 0. A non-root peer cannot issue a ticket.
An attempt with a wrong operation, peer, expired ticket or already-used token
fails without executing the privileged command.

The server performs an SQLite BEGIN IMMEDIATE/UPDATE/COMMIT, changing exactly
one unconsumed ticket to consumed *before* executing its fixed operation.
The operation is not repeated after a process interruption, failure or
client retry. Concurrent attempts on the same token produce at most one
successful consumption. SQLite synchronous=FULL is configured.

A consumed ticket is not refunded if the effect fails. The transaction does
**not** make SQLite consumption and the external effect atomic. If the broker
crashes between the commit and subprocess execution, the command may never run.
Do not claim exactly-once effects, rollback, durable task delivery or
revocation fencing from this prototype.

After reboot, outstanding tickets from the previous boot ID fail. The
prototype uses the host wall clock for expiration, so clock manipulation by a
privileged operator is outside its threat model.

## Important security limitation

On the current VM104, sentinelx still has **NOPASSWD: ALL**. Therefore it
can impersonate root through sudo, issue its own tickets, invoke privileged
code outside this broker and bypass the boundary entirely. This broker is
**not effective as an access-control measure in the current deployment**.

Do not install the broker or remove NOPASSWD: ALL in production yet.
The previous application-level gate, script_run_sudo_mode=deny/approval,
is also not sufficient: sudo=false scripts and exec operations can still
call sudo directly.

## Evidence

Local tests ran under a separate transient systemd unit with memory limits:
- 28 broker tests PASS, including parallel SQLite transactions, immutable
  command execution, expiry, wrong user/group, replay, boot identity and
  strict framing.
- Root-to-UID 992 host E2E PASS with a temporary root broker, root-owned
  socket/database and an actual systemd-run client with NoNewPrivileges=yes.
  Root-issued exact ticket executed the fixed audit-check only; a non-root
  issuer, replay, expired ticket and wrong operation were denied.
- Temporary test socket, database and root broker were all removed. No
  production daemon, firewall, sudoers, systemd override or workload changed.

## Next implementation gates

1. Define a trusted approver identity separate from the SentinelX service;
   prevent the service from escalating directly using sudo or other paths.
2. Add request-scoped authorization and durable issuance/consumption receipts
   with an independent immutable audit sink; include interrupted effect tests.
3. Add bounded broker supervision, restart/recovery, socket stale ownership
   checks, metrics, lock ownership and database retention.
4. Extend fixed operations for verified use cases and migrate consumers
   individually. Over one thousand privileged script_run requests per day
   currently exist; do not mass-replace them without semantic validation.
5. Deploy as a separate controlled canary, run failure/replay/fencing E2E,
   validate administrative recovery through an independent channel, then
   consider a restricted sudoers policy with rollback.

No existing project generated by Foundation is changed by this branch.
