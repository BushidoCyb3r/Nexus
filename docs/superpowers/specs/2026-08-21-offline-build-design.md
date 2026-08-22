# Offline build and airgapped import — design

Date: 2026-08-21
Status: approved, not yet implemented
Applies to: `nexus.py` 0.3.0-dev (branch `opencti-source` or later)

## 1. Problem

Nexus today assumes it runs on a Security Onion manager. `cmd_build()` calls
`check_env()` first and returns 1 if the Security Onion layout is absent, so the
tool cannot run anywhere else at all.

Two operators need it to:

- Someone whose Security Onion manager is airgapped. The manager cannot reach
  MISP, OpenCTI, or any other intelligence platform, so the file has to be built
  on a host that can, then carried across on removable media.
- Someone who simply wants to generate an `intel.dat` on a workstation without
  standing up Security Onion to do it.

## 2. Goals

1. `nexus.py` runs on any host with Python 3.6 and builds a complete, valid,
   drop-in `intel.dat` without a Security Onion installation present.
2. The resulting file can be moved to a manager and either
   (a) merged additively with `nexus.py --import FILE`, or
   (b) placed by hand at the intel path, with no nexus involvement on the
   manager at all.
3. Neither route can silently destroy indicators the manager had accumulated.
   Route (a) enforces that. Route (b) cannot, so nexus must state the
   consequence plainly rather than let the operator discover it in production.

## 3. Non-goals

- No new dependencies. Standard library only, as everywhere else in this tool.
- No second file format, archive, or package. Exactly one file crosses the
  airgap: `intel.dat` itself.
- No checksum or signature sidecar. See §8.
- No sync, no scheduling, no transport. Moving the file is the operator's job.

## 4. Existing structure this builds on

The Security Onion coupling is already tidy, which makes this small:

- Every Security Onion path is a named constant (`nexus.py:41-57`).
- `check_env()`, `run_guardrails()`, `seed_load_file()` and `apply_to_grid()`
  all take their directories as parameters with those constants as defaults.
- `run_guardrails()` already skips the `check_load_file` guardrail when
  `intel_dir is None`; its docstring anticipates exactly this case.
- `read_existing()` returns `(None, [])` for a missing file, so a first offline
  build needs no special-casing.
- `merge_additive()` and `write_atomic()` are source- and host-agnostic.

Nothing below the `flatten_*` seam changes. Fetch, mapping, normalisation,
filters, rendering, merge, backup and write are untouched.

## 5. Entering offline mode

The question is asked in `cmd_build()` **before** `check_env()`, since that call is
what currently aborts on a non-manager: is this file for this machine's Security
Onion, or for transfer to another host?  The interview then consumes the decided
mode at stage 8, where `output_path` and `apply` are already settled, so no new
interview stage is needed.

Per the project's standing rule, a flagless invocation always asks. The
`--offline` flag exists only so an unattended replay can skip the question, and
never changes what a flagless run means. The answer is recorded in the profile.

The *presented default* is derived from the host, and the derivation must
distinguish two cases that look similar and are not:

- `detect_so_version()` finds nothing **and** `SO_INTEL_DIR` does not exist:
  this is not a manager. Offline is the default answer.
- Security Onion **is** detected but its intel directory is missing or broken:
  this stays a hard error with the existing remediation. Offline must not
  become an escape hatch that masks a damaged manager.

## 6. What offline mode changes

Three things, and only three:

1. `check_env()` is not called. A new `check_output_target(path)` replaces it:
   the parent directory exists and is writable, and any file already at `path`
   passes lint. Failures are reported in the same `(level, message)` shape
   `check_env()` uses.
2. `run_guardrails()` is called with `intel_dir=None`, which skips
   `check_load_file`. Every content guardrail still runs — size, cap, and
   broad-indicator — as do lint and the append-only delta check.
3. The default output path becomes `./intel.dat` in the working directory
   rather than `SO_INTEL_FILE`, and the apply stage is replaced by printed
   transfer instructions (§7).

Offline still does `read_existing(output_path)` then `merge_additive`, so
repeated offline runs accumulate exactly as they do on a manager.

## 7. Transfer instructions

At the end of an offline run, nexus prints both manager-side routes and the
difference between them. This text is the feature's main safety mechanism for
route (b), so it states the consequence rather than implying it:

- `nexus.py --import FILE` merges additively. Every indicator already on the
  manager is preserved byte-for-byte; only unseen `(indicator, Intel::Type)`
  keys are added.
- Copying the file into place **replaces** what is there. That is safe on a
  fresh manager, and drops any accumulated indicators otherwise. It also
  requires `__load__.Zeek` to already be present, so the instructions name
  `--check-env` and `--seed`.

## 8. Import mode

`nexus.py --import /media/usb/intel.dat`

Argparse uses `dest="import_file"`, since `import` is a Python keyword.

No token, no network, no interview, no profile. The steps, in order:

1. Lint the incoming file on its own. Reject before touching anything.
2. Full `check_env()`, fatal on failure. Seed `__load__.Zeek` if missing, on
   the same terms `cmd_build()` uses.
3. `read_existing(SO_INTEL_FILE)`.
4. Header compatibility check. A file built with `meta.do_notice` cannot merge
   into one built without it, and vice versa. `cmd_build()` already blocks on
   this; import reuses the rule.
5. `merge_additive`.
6. `run_guardrails(..., intel_dir=SO_INTEL_DIR, append_only=True)`.
7. Lint the combined result.
8. Backup, then `write_atomic`.
9. `indicator_delta`; any removal is a hard invariant failure, not a prompt.
10. Offer the salt apply.

`--dry-run` and `--yes` behave as they do everywhere else in the tool.

### Why no checksum sidecar

Import is additive and lints what arrives. A truncated copy can only contribute
fewer rows, never remove one, and a corrupt line fails lint before anything is
written. A checksum would detect a condition that the existing checks already
render harmless.

## 9. Testing

- Offline build end to end into a temporary directory with no Security Onion
  layout present. Point the `SO_*` constants at a nonexistent poison path and
  assert nothing touches them.
- Import against a pre-seeded `intel.dat`: assert every pre-existing row is
  **byte-identical** afterwards, and that only unseen keys were appended.
- Import blocked on a `meta.do_notice` header mismatch — nothing written.
- Import blocked on a malformed incoming line — nothing written.
- A flagless offline run asks the mode question and honours a non-default
  answer, so a silent default to manager mode fails the test.
- `check_output_target` on: a missing parent, an unwritable parent, and an
  existing file that fails lint.

## 10. Open questions

None. Both manager-side routes are in scope and the merge model is settled.
