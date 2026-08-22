# Offline Build and Airgapped Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `nexus.py` build a complete, drop-in `intel.dat` on any host with no Security Onion installed, and let that file be merged into a manager's live `intel.dat` with `--import` without ever removing an existing indicator.

**Architecture:** Two additions to the existing single file. An *offline* build mode that swaps the Security Onion environment check for a small output-target check and skips the `__load__.Zeek` guardrail (which `run_guardrails` already supports via `intel_dir=None`), and an *import* mode that runs the existing merge/guardrail/lint/write pipeline against a file handed to it instead of against a live platform. Nothing below the `flatten_*` seam changes.

**Tech Stack:** Python 3.6 standard library only. `unittest`. No new files.

**Spec:** `docs/superpowers/specs/2026-08-21-offline-build-design.md`

## Global Constraints

Every task's requirements implicitly include all of these. They are copied verbatim from the project's standing rules; violating one is a task failure regardless of whether that task's own steps mention it.

- **Standard library only. No new dependencies, ever.**
- **Python 3.6 syntax floor.** No f-strings, no variable type hints, no dataclasses, no walrus operator, no `dict.fromisoformat`. Use `%`-formatting. The test suite runs on 3.9, so a 3.7+-only construct passes tests and fails in production — this has already happened once in this project.
- **One file.** All production code goes in `nexus.py`. All tests go in `test_nexus.py`.
- **Only `write_atomic()` writes the intel file.** No other code path may open the intel file for writing.
- **The merge is append-only by `(indicator, Intel::Type)`.** Existing rows survive byte-for-byte, in their original order. A computed removal is a hard invariant failure that blocks the write — never a prompt, never a warning.
- **The API token is never logged, never persisted to a profile, and never shown in any summary.**
- **Absent a command-line switch, the script asks.** Flags exist only to skip questions for unattended replay. A flagless invocation must run the full interview. There is no implicit default for anything the operator should be choosing.
- **Every non-trivial change lands with a test that fails without it.**
- Run the full suite with `python3 -m unittest test_nexus 2>&1 | tail -3` before every commit. It is currently **449 tests, OK**; the count only ever goes up.

---

### Task 1: `check_output_target()`

The offline path cannot call `check_env()` — there is no Security Onion to check. This is its replacement: it validates that the place we are about to write is usable, and nothing more.

**Files:**
- Modify: `nexus.py` — add to the `# ENVIRONMENT CHECK` section, after `check_env()` (which ends at `nexus.py:2131`)
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: `lint_file(path, do_notice=False)` (`nexus.py:1893`), which returns a list of problem strings.
- Produces: `check_output_target(path, do_notice=False)` returning `(ok, findings)` where `findings` is a list of `(level, message)` tuples and `level` is one of `"info"`, `"warn"`, `"error"`, `"fix"`. This is the exact shape `check_env()` returns, so callers can print both the same way.

- [ ] **Step 1: Write the failing tests**

Add to `test_nexus.py`:

```python
class TestCheckOutputTarget(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_writable_empty_target_is_ok(self):
        ok, findings = nexus.check_output_target(
            os.path.join(self.tmp, "intel.dat"))
        self.assertTrue(ok)
        levels = [level for level, _ in findings]
        self.assertNotIn("error", levels)

    def test_missing_parent_directory_is_an_error(self):
        ok, findings = nexus.check_output_target(
            os.path.join(self.tmp, "nope", "intel.dat"))
        self.assertFalse(ok)
        self.assertIn("error", [level for level, _ in findings])

    def test_unwritable_parent_directory_is_an_error(self):
        locked = os.path.join(self.tmp, "locked")
        os.mkdir(locked, 0o500)
        self.addCleanup(os.chmod, locked, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        ok, findings = nexus.check_output_target(
            os.path.join(locked, "intel.dat"))
        self.assertFalse(ok)
        self.assertIn("error", [level for level, _ in findings])

    def test_existing_file_that_fails_lint_is_an_error(self):
        path = os.path.join(self.tmp, "intel.dat")
        with open(path, "w") as handle:
            handle.write(nexus.header_line(False) + "\n")
            handle.write("this-is-not-a-valid-row\n")
        ok, findings = nexus.check_output_target(path)
        self.assertFalse(ok)
        joined = " ".join(message for _, message in findings)
        self.assertIn("lint", joined)

    def test_existing_clean_file_is_reported_but_ok(self):
        path = os.path.join(self.tmp, "intel.dat")
        nexus.write_atomic(path, [nexus.header_line(False),
                                  "evil.example\tIntel::DOMAIN\tt\td\t-"])
        ok, findings = nexus.check_output_target(path)
        self.assertTrue(ok)
        joined = " ".join(message for _, message in findings)
        self.assertIn("1 indicator", joined)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_nexus.TestCheckOutputTarget -v`
Expected: FAIL, `AttributeError: module 'nexus' has no attribute 'check_output_target'`

- [ ] **Step 3: Write the implementation**

Add to `nexus.py` immediately after `check_env()`:

```python
def check_output_target(path, do_notice=False):
    """Stage 0 for an offline build.  Returns (ok, findings).

    check_env() asks whether this machine is a working Security Onion manager.
    Off-box there is no such question to ask -- the only thing that matters is
    whether the file we are about to write can be written, and whether
    anything already sitting at that path is something we can safely merge
    with.  Same return shape as check_env() so callers print both alike.
    """
    findings = []
    directory = os.path.dirname(os.path.abspath(path)) or "."

    if not os.path.isdir(directory):
        findings.append(("error", "output directory does not exist: %s"
                                  % directory))
        findings.append(("fix", "mkdir -p %s" % directory))
        return False, findings
    if not os.access(directory, os.W_OK):
        findings.append(("error", "output directory is not writable: %s"
                                  % directory))
        return False, findings
    findings.append(("info", "output directory: %s" % directory))

    if not os.path.exists(path):
        findings.append(("info", "%s will be created" % path))
        return True, findings

    _, rows = read_existing(path)
    findings.append(("info", "existing file: %d indicator(s) in %s"
                             % (len(rows), path)))
    try:
        problems = lint_file(path, do_notice)
    except (OSError, UnicodeDecodeError) as exc:
        findings.append(("error", "existing file is unreadable: %s" % exc))
        return False, findings
    if problems:
        findings.append(("error", "existing file has %d lint problem(s); "
                                  "refusing to merge into it" % len(problems)))
        findings.append(("fix", "run --lint %s for detail" % path))
        return False, findings
    return True, findings
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest test_nexus.TestCheckOutputTarget -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Run the full suite**

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 454 tests

- [ ] **Step 6: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: check_output_target for builds with no Security Onion present"
```

---

### Task 2: The `--offline` flag and the mode decision

The mode has to be settled *before* `check_env()` runs, because that call is what currently aborts on a non-manager (`nexus.py:4085`). This task adds the flag and the decision function but does not yet wire either into `cmd_build` — that is Task 4.

**Files:**
- Modify: `nexus.py` — `build_parser()` (`nexus.py:4026-4037`, the "unattended operation" group), and add `resolve_build_target()` to the `# INTERVIEW` section next to the other `ask_*` helpers
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: `ask_choice(prompt, options, default=None, input_fn=input)` (`nexus.py:2411`), `detect_so_version()` (`nexus.py:2024`), `SO_INTEL_DIR` (`nexus.py:41`).
- Produces:
  - `args.offline` — a bool, default `False`.
  - `resolve_build_target(args, input_fn=input, intel_dir=SO_INTEL_DIR)` returning `True` for an offline build and `False` for a manager build.

- [ ] **Step 1: Write the failing tests**

The third test is the one that matters most — it proves the standing interactivity rule, so it answers the *non-default* option. A silent default would pass a test that answered the default.

```python
class TestResolveBuildTarget(unittest.TestCase):
    def _args(self, **kw):
        return argparse.Namespace(offline=kw.get("offline", False))

    def test_offline_flag_skips_the_question(self):
        def refuse(_prompt):
            raise AssertionError("must not ask when --offline is given")
        self.assertTrue(nexus.resolve_build_target(
            self._args(offline=True), input_fn=refuse))

    def test_flagless_run_asks(self):
        asked = []

        def record(prompt):
            asked.append(prompt)
            return ""
        nexus.resolve_build_target(self._args(), input_fn=record,
                                   intel_dir="/nonexistent/so/intel")
        self.assertTrue(asked, "a flagless run must ask which target")

    def test_flagless_run_honours_a_non_default_answer(self):
        # No Security Onion here, so the default is offline.  Answering
        # "manager" must be obeyed -- a silent default would return True.
        self.assertFalse(nexus.resolve_build_target(
            self._args(), input_fn=lambda _p: "manager",
            intel_dir="/nonexistent/so/intel"))

    def test_default_is_offline_when_no_security_onion_present(self):
        self.assertTrue(nexus.resolve_build_target(
            self._args(), input_fn=lambda _p: "",
            intel_dir="/nonexistent/so/intel"))

    def test_default_is_manager_when_intel_dir_exists(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        self.assertFalse(nexus.resolve_build_target(
            self._args(), input_fn=lambda _p: "", intel_dir=tmp))


class TestOfflineFlagParsing(unittest.TestCase):
    def test_offline_defaults_to_false(self):
        args = nexus.build_parser().parse_args([])
        self.assertFalse(args.offline)

    def test_offline_flag_sets_true(self):
        args = nexus.build_parser().parse_args(["--offline"])
        self.assertTrue(args.offline)
```

If `argparse` is not already imported in `test_nexus.py`, add it.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_nexus.TestResolveBuildTarget test_nexus.TestOfflineFlagParsing -v`
Expected: FAIL — no `resolve_build_target`, and `--offline` is an unrecognised argument.

- [ ] **Step 3: Add the flag**

In `build_parser()`, in the `run` ("unattended operation") group, after the `--profile` argument:

```python
    run.add_argument("--offline", action="store_true",
                     help="build for transfer to another host; skips the "
                          "Security Onion checks and the apply step. Asked "
                          "if omitted.")
```

- [ ] **Step 4: Add the decision function**

Add to the `# INTERVIEW` section, after `ask_choice()`:

```python
def resolve_build_target(args, input_fn=input, intel_dir=SO_INTEL_DIR):
    """True for an offline build, False for a build on this manager.

    Asked before check_env(), because check_env() is what refuses to run on a
    host with no Security Onion.  The presented default is derived, but the
    question is always asked when the flag is absent -- flags skip questions
    for unattended replay, they do not change what a flagless run means.

    A missing Security Onion means "not a manager".  A *broken* Security Onion
    is a different thing and stays a hard error in check_env(); offline mode
    must never become a way to paper over a damaged manager.
    """
    if getattr(args, "offline", False):
        return True
    on_manager = detect_so_version() is not None or os.path.isdir(intel_dir)
    default = "manager" if on_manager else "offline"
    choice = ask_choice(
        "Where is this intel.dat going?",
        [("manager", "this machine's Security Onion"),
         ("offline", "another host -- write it here and transfer it")],
        default, input_fn)
    return choice == "offline"
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m unittest test_nexus.TestResolveBuildTarget test_nexus.TestOfflineFlagParsing -v`
Expected: PASS, 7 tests

- [ ] **Step 6: Run the full suite and check `--help`**

```bash
python3 -m unittest test_nexus 2>&1 | tail -3
python3 nexus.py --help | grep -A2 offline
```
Expected: `OK`, 461 tests; `--offline` documented.

- [ ] **Step 7: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: --offline flag and the build-target question"
```

---

### Task 3: The interview honours offline mode

Stage 8 currently asks for a Security Onion deployment topology and whether to apply to the grid. Neither question means anything off-box, and its default output path points at a Security Onion directory that does not exist there.

**Files:**
- Modify: `nexus.py` — `_stage8_output()` (the `_stage(8, "Output and apply")` block at `nexus.py:3034-3064`) and `run_interview()` (`nexus.py:3067`)
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: `resolve_build_target()` from Task 2 (the caller decides; the interview is *told*).
- Produces:
  - `run_interview(client, input_fn=input, getpass_fn=getpass.getpass, source=None, offline=False)`
  - `config["offline"]` — bool, persisted in the profile.
  - When `offline` is true: `config["output_path"]` defaults to `"./intel.dat"`, `config["deployment"]` is `"offline"`, and `config["apply"]` is `False` without asking.

Note the exact name of the stage-8 function before editing — locate it with `grep -n '_stage(8' nexus.py` and read the enclosing `def`.

- [ ] **Step 1: Write the failing tests**

```python
class TestOfflineInterview(unittest.TestCase):
    def _run(self, answers, offline):
        supplied = list(answers)

        def feed(_prompt):
            return supplied.pop(0) if supplied else ""
        return nexus.run_interview(None, input_fn=feed,
                                   getpass_fn=lambda _p: "tok",
                                   source="misp", offline=offline)

    def test_offline_defaults_output_to_the_working_directory(self):
        config = self._run([], offline=True)
        self.assertEqual(config["output_path"], "./intel.dat")

    def test_offline_never_applies(self):
        config = self._run([], offline=True)
        self.assertFalse(config["apply"])
        self.assertEqual(config["deployment"], "offline")

    def test_offline_flag_is_recorded_in_the_config(self):
        self.assertTrue(self._run([], offline=True)["offline"])
        self.assertFalse(self._run([], offline=False)["offline"])

    def test_manager_mode_still_defaults_to_the_security_onion_path(self):
        config = self._run([], offline=False)
        self.assertEqual(config["output_path"], nexus.SO_INTEL_FILE)

    def test_offline_is_not_dropped_by_a_profile_round_trip(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "p.json")
        nexus.save_profile(self._run([], offline=True), path)
        self.assertTrue(nexus.load_profile(path)["offline"])
```

The interview asks many questions; `feed` returning `""` accepts each default, which is what these tests want. If a question has no default and raises, supply the needed answers in the `answers` list for that test only.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_nexus.TestOfflineInterview -v`
Expected: FAIL — `run_interview()` got an unexpected keyword argument `offline`.

- [ ] **Step 3: Thread `offline` through**

Change the `run_interview` signature and its stage-8 call:

```python
def run_interview(client, input_fn=input, getpass_fn=getpass.getpass,
                  source=None, offline=False):
```

Pass `offline=offline` into the stage-8 helper, and add the parameter to that helper's signature.

- [ ] **Step 4: Branch inside stage 8**

Replace the deployment/output/apply parts of stage 8 with:

```python
    config["offline"] = bool(offline)
    if offline:
        # Neither question has a meaning off-box: there is no grid to pick a
        # topology for, and nothing to apply to.
        config["deployment"] = "offline"
        config["output_path"] = ask_required("Output path", "./intel.dat",
                                             input_fn)
    else:
        config["deployment"] = ask_choice(
            "Security Onion deployment",
            [("distributed", "manager plus sensor grid"),
             ("standalone", "one standalone node")],
            "distributed", input_fn)
        config["output_path"] = ask_required("Output path", SO_INTEL_FILE,
                                             input_fn)
```

and guard the apply question at the end of the same function:

```python
    if offline:
        config["apply"] = False
    else:
        target = ("standalone node" if config["deployment"] == "standalone"
                  else "grid")
        config["apply"] = ask_yes_no(
            "Apply to the %s after writing?" % target, False, input_fn)
    return config
```

Leave the `merge_mode`, `backup`, `max_indicators`, `dry_run` and profile questions exactly as they are — every one of them is meaningful offline.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m unittest test_nexus.TestOfflineInterview -v`
Expected: PASS, 5 tests

- [ ] **Step 6: Run the full suite**

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 466 tests. If any pre-existing interview test fails, it is asserting on the stage-8 question sequence — read it and confirm the manager path is genuinely unchanged before touching the test.

- [ ] **Step 7: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: interview skips the Security Onion questions when offline"
```

---

### Task 4: The offline branch in `cmd_build`

**Files:**
- Modify: `nexus.py` — `cmd_build()` (`nexus.py:4083`), both the environment check at the top and the apply block at the bottom
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: `check_output_target()` (Task 1), `resolve_build_target()` (Task 2), `config["offline"]` (Task 3).
- Produces: `print_transfer_instructions(path, do_notice=False)`, which writes the two manager-side routes to stdout.

- [ ] **Step 1: Write the failing test**

This is the end-to-end guard. Pointing every `SO_*` constant at a path that does not exist proves the offline run never depends on one.

```python
class TestOfflineBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.poison = "/nonexistent/security-onion"
        for name in ("SO_INTEL_DIR", "SO_INTEL_DEFAULT_DIR",
                     "SO_INTEL_RUNTIME_DIR"):
            patcher = mock.patch.object(nexus, name, self.poison)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_offline_build_writes_without_any_security_onion(self):
        out = os.path.join(self.tmp, "intel.dat")
        config = {
            "offline": True, "output_path": out, "deployment": "offline",
            "apply": False, "backup": False, "dry_run": False,
            "do_notice": False, "source": "misp", "types": ["ip-dst"],
            "exclude_private": True, "own_networks": [], "own_domains": [],
            "allowlist_file": None, "split_composites": "both",
            "allow_subnet": True, "source_fmt": "MISP",
            "desc_template": "{category}", "source_base_url": None,
            "meta_maxlen": 200, "max_indicators": None, "token": "t",
        }
        rc = self._build_with(config)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out))
        header, rows = nexus.read_existing(out)
        self.assertEqual(header, nexus.header_line(False))
        self.assertTrue(rows)
```

Write `_build_with` as a helper on the test class that patches `run_interview` to return `config`, patches `make_client` and `_fetch_records` to return one fake record, builds an `argparse.Namespace` with the flags `cmd_build` reads (`profile`, `yes`, `dry_run`, `diff`, `offline`, plus whatever `resolve_token` needs), and calls `nexus.cmd_build(args)`. Model it on the existing end-to-end test class — find it with `grep -n 'class TestOpenctiEndToEnd' test_nexus.py` and follow its fixture style rather than inventing a new one.

Add a second test asserting the transfer text appears, capturing stdout the way the existing suite does:

```python
    def test_offline_build_prints_both_transfer_routes(self):
        out = os.path.join(self.tmp, "intel.dat")
        text = self._build_capturing_stdout(out)
        self.assertIn("--import", text)
        self.assertIn("replaces", text)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_nexus.TestOfflineBuild -v`
Expected: FAIL — `cmd_build` calls `check_env()`, which returns not-ok against the poison paths, and returns 1.

- [ ] **Step 3: Add the transfer-instruction printer**

Add to the `# APPLY` section of `nexus.py`:

```python
def print_transfer_instructions(path, do_notice=False):
    """Both manager-side routes, and the difference between them.

    An operator who copies the file into place by hand gets no guardrails and
    no merge -- that route is supported, but it silently replaces whatever the
    manager had accumulated.  Saying so here is the only protection it gets.
    """
    print("\nBuilt for transfer: %s" % path)
    print("\nOn the Security Onion manager, either:")
    print("  1. Merge it (keeps the indicators already there):")
    print("       python3 nexus.py --import %s" % os.path.basename(path))
    print("  2. Or put it in place by hand:")
    print("       sudo cp %s %s/" % (os.path.basename(path), SO_INTEL_DIR))
    print("     This REPLACES the manager's intel.dat. Safe on a fresh")
    print("     install; on a manager that has been running, it drops every")
    print("     indicator not in this file.")
    print("     It also needs %s already present -- check with:" % SO_LOAD_FILE)
    print("       python3 nexus.py --check-env    (and --seed if it is missing)")
    print("\nThen apply: %s" % SO_APPLY_CMD)
```

- [ ] **Step 4: Branch the environment check**

At the top of `cmd_build()`, replace the unconditional `ok, findings = check_env()` block with:

```python
    offline = resolve_build_target(args)
    if offline:
        ok, findings = True, []   # checked against the real path once known
    else:
        ok, findings = check_env()
```

and leave the existing seeding/abort logic inside the `else` branch untouched. `resolve_build_target` may raise `InterviewAborted`; wrap the call in the same `try` the interview uses, returning 130.

For a `--profile` replay the profile already records the answer, so after the config is loaded:

```python
    if args.profile:
        offline = bool(config.get("offline", offline))
```

- [ ] **Step 5: Check the output target once the path is known**

Immediately after `path = config["output_path"]`:

```python
    if config.get("offline"):
        ok, findings = check_output_target(path, config["do_notice"])
        for level, message in findings:
            print(LEVEL_PREFIX.get(level, "  ") + message)
        if not ok:
            return 1
```

- [ ] **Step 6: Pass `intel_dir=None` to the guardrails when offline**

Change the `run_guardrails` call so the `intel_dir` argument becomes:

```python
        intel_dir=None if config.get("offline") else os.path.dirname(path),
```

`run_guardrails` already skips `check_load_file` when `intel_dir` is None (`nexus.py:2298`); no change is needed there.

- [ ] **Step 7: Replace the apply block for offline runs**

In the tail of `cmd_build()`, before the existing `if not config.get("apply"):` block:

```python
    if config.get("offline"):
        print_transfer_instructions(path, config["do_notice"])
        return 0
```

- [ ] **Step 8: Wire `offline` into the interview call**

```python
            config = run_interview(None, offline=offline)
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `python3 -m unittest test_nexus.TestOfflineBuild -v`
Expected: PASS

- [ ] **Step 10: Run the full suite**

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 468 tests

- [ ] **Step 11: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: offline build mode in cmd_build"
```

---

### Task 5: `--import`

**Files:**
- Modify: `nexus.py` — `build_parser()` modes group, `main()` dispatch (`nexus.py:4051-4058`), and a new `cmd_import()` in the `# MAIN` section
- Test: `test_nexus.py`

**Interfaces:**
- Consumes: `lint_file`, `check_env`, `seed_load_file`, `read_existing`, `header_line`, `merge_additive`, `run_guardrails`, `lint_lines`, `backup_file`, `write_atomic`, `indicator_delta`, `summarise_delta`, `apply_to_grid`.
- Produces: `cmd_import(args)` returning an exit code, and `args.import_file`.

- [ ] **Step 1: Write the failing tests**

The first test is the invariant. Assert byte-equality of the pre-existing rows, not merely that they are present.

```python
class TestImportMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.intel_dir = os.path.join(self.tmp, "intel")
        os.makedirs(self.intel_dir)
        open(os.path.join(self.intel_dir, nexus.SO_LOAD_FILE), "w").close()
        self.live = os.path.join(self.intel_dir, "intel.dat")
        self.incoming = os.path.join(self.tmp, "incoming.dat")

    def _write(self, path, rows, do_notice=False):
        nexus.write_atomic(path, [nexus.header_line(do_notice)] + rows)

    def _args(self, **kw):
        return argparse.Namespace(
            import_file=kw.get("import_file", self.incoming),
            yes=kw.get("yes", True), dry_run=kw.get("dry_run", False),
            diff=False)

    def test_existing_rows_survive_byte_for_byte(self):
        old = "old.example\tIntel::DOMAIN\tMISP\tdesc\t-"
        new = "new.example\tIntel::DOMAIN\tMISP\tdesc\t-"
        self._write(self.live, [old])
        self._write(self.incoming, [new])
        rc = self._import()
        self.assertEqual(rc, 0)
        _, rows = nexus.read_existing(self.live)
        self.assertEqual(rows[0], old)      # byte-identical, still first
        self.assertIn(new, rows)
        self.assertEqual(len(rows), 2)

    def test_duplicate_key_does_not_duplicate_the_row(self):
        row = "dup.example\tIntel::DOMAIN\tMISP\tdesc\t-"
        self._write(self.live, [row])
        self._write(self.incoming,
                    ["dup.example\tIntel::DOMAIN\tOTHER\tother\t-"])
        self._import()
        _, rows = nexus.read_existing(self.live)
        self.assertEqual(rows, [row])       # existing wins, no second row

    def test_header_mismatch_blocks_and_writes_nothing(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"], False)
        before = open(self.live).read()
        self._write(self.incoming,
                    ["b.example\tIntel::DOMAIN\tMISP\td\tT"], True)
        self.assertEqual(self._import(), 1)
        self.assertEqual(open(self.live).read(), before)

    def test_malformed_incoming_file_blocks_and_writes_nothing(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        before = open(self.live).read()
        with open(self.incoming, "w") as handle:
            handle.write(nexus.header_line(False) + "\n")
            handle.write("garbage-with-no-tabs\n")
        self.assertEqual(self._import(), 1)
        self.assertEqual(open(self.live).read(), before)

    def test_missing_incoming_file_is_an_error(self):
        self._write(self.live, ["a.example\tIntel::DOMAIN\tMISP\td\t-"])
        self.assertEqual(
            self._import(import_file=os.path.join(self.tmp, "nope")), 2)
```

`_import` patches `nexus.SO_INTEL_DIR` and `nexus.SO_INTEL_FILE` to the fixture's paths, patches `check_env` to return `(True, [])`, and calls `nexus.cmd_import(self._args(**kw))`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_nexus.TestImportMode -v`
Expected: FAIL — no `cmd_import`.

- [ ] **Step 3: Add the flag**

In the `mode` group of `build_parser()`:

```python
    mode.add_argument("--import", dest="import_file", metavar="PATH",
                      default=None,
                      help="merge an intel.dat built on another host into "
                           "this manager's file, append-only")
```

`dest` is mandatory — `import` is a Python keyword, so `args.import` would be a syntax error at every use site.

- [ ] **Step 4: Dispatch it**

In `main()`, alongside the other mode checks and **above** the `--yes requires --profile` gate:

```python
    if args.import_file:
        return cmd_import(args)
```

The placement matters. `--import` runs no interview, so `--import --yes` is a legitimate unattended invocation and must not be rejected by a gate that exists to catch unanswerable interviews.

- [ ] **Step 5: Write `cmd_import`**

```python
def cmd_import(args):
    """Merge an intel.dat built elsewhere into this manager's file.

    Everything here already exists for cmd_build; the only new thing is where
    the rows come from.  The append-only invariant is enforced identically --
    an import that would remove an indicator is a bug, not a decision.
    """
    incoming = args.import_file
    if not os.path.exists(incoming):
        print("no such file: %s" % incoming, file=sys.stderr)
        return 2

    incoming_header, incoming_rows = read_existing(incoming)
    if not incoming_rows:
        print("%s contains no indicators" % incoming, file=sys.stderr)
        return 2
    do_notice = bool(incoming_header
                     and incoming_header == header_line(True))
    problems = lint_file(incoming, do_notice)
    if problems:
        print("Refusing to import, %s fails lint:" % incoming)
        for problem in problems[:10]:
            print("  " + problem)
        return 1
    print("importing %d indicator(s) from %s" % (len(incoming_rows), incoming))

    ok, findings = check_env()
    if not ok:
        for level, message in findings:
            if level in ("error", "fix"):
                print(LEVEL_PREFIX.get(level, "  ") + message)
        missing_load = not os.path.exists(
            os.path.join(SO_INTEL_DIR, SO_LOAD_FILE))
        if missing_load and os.path.isdir(SO_INTEL_DIR) and (
                args.yes or ask_yes_no(
                    "Seed the intel directory from the Security Onion "
                    "defaults?", True)):
            try:
                for path in seed_load_file():
                    print("  copied %s" % path)
            except OSError as exc:
                print("  could not seed: %s" % exc)
                return 1
            ok, _ = check_env()
        if not ok:
            print("Environment is not ready -- run --check-env for detail.")
            return 1

    path = SO_INTEL_FILE
    existing_header, existing = read_existing(path)
    wanted_header = header_line(do_notice)
    if existing_header and existing_header != wanted_header:
        print("\nBlocked. %s was built with a different meta.do_notice "
              "setting than %s; append-only mode will not rewrite existing "
              "rows." % (incoming, path))
        return 1

    combined = merge_additive(existing, incoming_rows)
    lines = [wanted_header] + combined

    verdicts = run_guardrails([], len(existing), intel_dir=SO_INTEL_DIR,
                              append_only=True)
    print("\nGuardrails")
    blocked = False
    for verdict in verdicts:
        print("  %-7s %s" % (verdict.level, verdict.message))
        blocked = blocked or not verdict.ok
    if blocked:
        print("\nBlocked. Nothing written.")
        return 1

    problems = lint_lines(lines, do_notice)
    if problems:
        print("\nRefusing to write, the merged file fails lint:")
        for problem in problems[:10]:
            print("  " + problem)
        return 1

    added, removed = indicator_delta(existing, lines)
    print("\nIndicator diff")
    print(summarise_delta(existing, lines))
    if removed:
        print("\nBlocked. Import unexpectedly removed indicators.")
        return 1

    if args.dry_run:
        print("\nDry run -- nothing written to %s" % path)
        return 0

    saved = backup_file(path, os.path.join(NEXUS_HOME, "backups"))
    if saved:
        print("\nbacked up to %s" % saved)
    write_atomic(path, lines)
    print("added %d new indicators; %d total in %s"
          % (len(added), len(combined), path))

    if not (args.yes or ask_yes_no("Apply to the grid now?", False)):
        print("\nNot applied. To push it:")
        print("  %s" % SO_APPLY_CMD)
        return 0
    applied, steps = apply_to_grid(intel_dir=SO_INTEL_DIR,
                                   expected=len(combined))
    for level, message in steps:
        print(LEVEL_PREFIX.get(level, "  ") + message)
    return 0 if applied else 1
```

Note `run_guardrails([], len(existing), ...)`: the content guardrails take *parsed rows*, and import has raw lines rather than the tuple form `build_indicators` produces. Passing an empty row list keeps `check_size` and `check_load_file` meaningful while skipping `check_broad_indicators`, which has nothing to inspect. The incoming file's content was already validated by `lint_file` in step one. If a reviewer disagrees, the alternative is a line-to-tuple parser, which is new surface for no new protection.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python3 -m unittest test_nexus.TestImportMode -v`
Expected: PASS, 5 tests

- [ ] **Step 7: Run the full suite**

Run: `python3 -m unittest test_nexus 2>&1 | tail -3`
Expected: `OK`, 473 tests

- [ ] **Step 8: Commit**

```bash
git add nexus.py test_nexus.py
git commit -m "feat: --import merges an intel.dat built on another host"
```

---

### Task 6: Documentation and version

**Files:**
- Modify: `nexus.py` (module docstring and `__version__` at `nexus.py:30`), `HANDOFF.md`, `PLAN.md`
- Test: none — verified by running the commands the docs claim

- [ ] **Step 1: Bump the version**

`__version__ = "0.4.0-dev"`, and add the two new modes to the module docstring's mode list.

- [ ] **Step 2: Update `HANDOFF.md`**

Add to the quick-command block: `--offline` and `--import PATH`. Add to the "things that will bite you" section the one that actually will:

> Copying an offline-built `intel.dat` into place by hand **replaces** the manager's file. `--import` merges; `cp` does not. On a manager that has been running, hand-placement drops every indicator not in the transferred file. This is supported and documented rather than blocked, because an operator with no Python on the manager has no other route.

Update the architecture table with `check_output_target`, `resolve_build_target`, `print_transfer_instructions` and `cmd_import`, and recheck every line number in that table — section banners shift when the docstring changes.

- [ ] **Step 3: Update `PLAN.md`**

Add offline build and import to the phase table. Record in the scope section that a checksum sidecar and a package format were considered and rejected, with the §8 reasoning from the spec.

- [ ] **Step 4: Verify the docs against the code**

```bash
python3 nexus.py --help
python3 nexus.py --version
python3 -m unittest test_nexus 2>&1 | tail -3
grep -n '^# [A-Z]' nexus.py
```
Every flag named in either document must appear in `--help`; every line number in the `HANDOFF.md` architecture table must match the `grep` output. Do not eyeball this — compare the lists.

- [ ] **Step 5: Commit**

```bash
git add nexus.py HANDOFF.md PLAN.md
git commit -m "docs: document offline build and airgapped import"
```

---

## Self-Review

**Spec coverage.** §5 entering offline mode → Task 2 (decision, flag, derived default, the manager-vs-broken-manager distinction) and Task 3 (interview). §6's three changes → Task 1 + Task 4 steps 5, 6 and 7. §7 transfer instructions → Task 4 step 3. §8 import, all ten steps → Task 5. §9 testing → the test steps of Tasks 1, 3, 4 and 5; the poison-path assertion is Task 4 step 1, the byte-identity assertion is Task 5 step 1. §3 non-goals are enforced by omission — no task adds a dependency, a file, or a checksum.

**Placeholder scan.** No TBDs. Two steps deliberately say "model it on the existing fixture" rather than reproducing a large fixture verbatim (Task 4 step 1, Task 5 step 1) and both name the exact class to copy and the exact `grep` to find it.

**Type consistency.** `check_output_target(path, do_notice=False) -> (bool, [(level, message)])` matches `check_env`'s shape and is called that way in Task 4. `resolve_build_target(args, input_fn, intel_dir) -> bool` is produced in Task 2 and consumed in Task 4 step 4. `config["offline"]` is written in Task 3 and read in Task 4 steps 5, 6 and 7. `args.import_file` is defined in Task 5 step 3 and read in steps 4 and 5. `print_transfer_instructions(path, do_notice=False)` is defined in Task 4 step 3 and called in step 7.

**One risk flagged for the executor.** Task 5's `run_guardrails([], len(existing), ...)` passes an empty row list because import has lines rather than parsed tuples. The reasoning is written into the task. A reviewer who rejects it should say so rather than silently adding a parser.
