# Privileged script_run admission (staged, opt-in)

## Scope and operating modes

This change adds application-level admission for script_run requests with sudo=true on POSIX. The default, legacy, is fully backward-compatible. Configure security.script_run_sudo_mode to one of:

- legacy: preserve existing behavior.
- deny: reject sudo=true before preparing any script or invoking a child process.
- approval: require a root-owned, exact, time-limited operator approval.

Unknown modes fail during policy loading, not at script execution. The mode is chosen by the host operator, not by a per-request field.

## Exact approvals

Approval mode reads only /etc/sentinelx/privileged-script-approvals.json, which must be a regular root-owned file, have one link, not be writable by group or others, and be at most 64 KiB. Its parent must be root-owned and not writable by group or others. Symlinks at the final path component are rejected.

A manifest must contain exactly schema=1 and approvals: a list of at most 128 records. Each record has exactly fingerprint, issued_at and expires_at. The fingerprint is a lowercase 64-character SHA-256 of the canonical request; both timestamps must be timezone-aware ISO-8601, and lifetime cannot exceed one hour.

The fingerprint covers interpreter, SHA-256 of the script content, all positional arguments, exact cwd, complete environment name and values, timeout and background flag. The feature does not persist script bodies or secrets in approval files. Operators must review the whole script and parameters before granting an approval. A digest alone is not meaningful code review.

Approvals may be reused for identical requests within the one-hour window. This prototype does not implement single-use tickets, requester identity binding or atomic ticket consumption. A future root-owned privileged broker must supply those protections.

## Critical limitations

The current script_run(sudo=false) can still invoke sudo inside arbitrary Python or Bash content. Other agent operations may also launch sudo. On a host with NOPASSWD: ALL, this application-level approval feature is not a Linux privilege boundary and is bypassable by untrusted script content.

DO NOT remove NOPASSWD: ALL merely because this feature is present. A protected root broker, atomic one-use tickets, host/requester binding, approved side-effect definitions and a fully migrated execution path are required first.

This branch changes NO running services, no installed agent config, no sudoers, no existing scripts and no live workloads. The staged policy remains legacy by default.

## Required production gates

1. Implement a root-owned privileged broker with an exact sudoers entry or protected Unix socket.
2. Authorize only fixed operations or exact, expiring, one-use approvals at the broker. Log receipts without sensitive contents.
3. Prevent arbitrary script_run and exec from retaining independent sudo access.
4. Validate end-to-end authorization, denial, expiry, replay protection, process termination, restart and rollback as the actual SentinelX service identity.
5. Apply a reviewed, tested sudoers cutover only after all necessary workloads have migrated.

## Validation approach

Run tests under bounded transient systemd units, not under the SentinelX agent cgroup. Test legacy compatibility, denied requests before staging, unprivileged execution, exact fingerprint binding, expiration, malformed approval files and invalid configuration.
