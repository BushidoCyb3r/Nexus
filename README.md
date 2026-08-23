# Nexus

Nexus builds a Zeek Intel framework `intel.dat` from a threat intelligence
platform, and puts it where Security Onion will load it.

It pulls from **MISP**, **OpenCTI** or a **TAXII 2.0/2.1** server, maps what it
finds to Zeek `Intel::Type` values, filters it, and merges the result into the
manager's existing file **append-only** — an indicator that is already there is
never rewritten and never removed.

One file, no dependencies. Python 3.6 or newer, standard library only.

---

## Install

Copy `nexus.py` onto the machine that will run it. That is the whole install.

On a Security Onion manager, the conventional home is `/opt/nexus`:

```
sudo mkdir -p /opt/nexus/{profiles,logs,backups}
sudo cp nexus.py /opt/nexus/
sudo chmod 750 /opt/nexus
```

Check the manager is fit to be written to before anything else:

```
sudo /opt/nexus/nexus.py --check-env
```

That verifies the Security Onion intel directory exists and that
`__load__.Zeek` is present. **Without `__load__.Zeek`, Zeek silently ignores
`intel.dat`** — nothing errors, no indicator ever matches, and the failure
looks exactly like success. If it is missing:

```
sudo /opt/nexus/nexus.py --seed
```

---

## Building a file

Run it with no flags. Nexus interviews you: which platform, where it is, what
to pull, what to exclude, where to write, and whether to push the result to the
grid.

```
sudo /opt/nexus/nexus.py
```

Flags exist only to skip questions for an unattended replay. A flagless run
always asks — no flag changes what a flagless run means.

Useful ones:

| Flag | What it does |
|---|---|
| `--probe` | Connect and report available IOC counts. Builds nothing. |
| `--dry-run` | Build to a temp file and show the diff. Writes nothing live. |
| `--diff` | Show what would change against the current file. |
| `--explain` | Print the resolved platform query for a saved profile. Contacts nothing. |
| `--lint PATH` | Validate an `intel.dat` and exit. |
| `--apply` | Push the existing file to the grid and check the reporter log. |

At the end of the interview Nexus offers to save your answers as a **profile**
under `/opt/nexus/profiles/`. Replay it with:

```
sudo /opt/nexus/nexus.py --profile misp --yes
```

### Credentials are never stored in a profile

A profile records *what* you query, never *who you are*. The API token is never
written to it, never logged, and never shown in any summary. For an unattended
run the token is read, in order, from:

1. `--token-file PATH`
2. `NEXUS_TOKEN` or `NEXUS_MISP_TOKEN` in the environment
3. `/opt/nexus/credentials.json`

TAXII with Basic authentication needs a second secret, the username. It is
treated the same way and read from `NEXUS_TAXII_USERNAME`.

---

## Airgapped managers

If the manager cannot reach the intelligence platform, build the file somewhere
that can and carry it across.

On the connected host — no Security Onion needed:

```
python3 nexus.py --offline
```

That writes a complete, drop-in `intel.dat` to a path you choose. Move it to
the manager, then pick one of two routes:

**Merge it (recommended).** Every indicator already on the manager is kept
byte-for-byte; only unseen `(indicator, Intel::Type)` pairs are added.

```
sudo /opt/nexus/nexus.py --import /media/usb/intel.dat
```

**Copy it into place.** This **replaces** the file. That is fine on a fresh
manager and drops everything the manager had accumulated otherwise. The
destination file must be named `intel.dat` — a copy under any other name lands
beside the real one where Zeek never reads it.

```
sudo cp /media/usb/intel.dat /opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat
sudo salt -C 'I@zeek:enabled:true' state.apply zeek
```

---

## Running on a schedule

Nexus never installs a timer on its own. Ask for one:

```
sudo /opt/nexus/nexus.py --install-timer
```

It asks which saved profile to run and how often, prints the exact contents of
both unit files, and asks before writing them. Nothing is enabled — it hands
you the commands and stops.

Before writing anything it checks the things that would otherwise fail at 02:00
with nobody watching: that this host runs systemd, that the unit directory is
writable, that the profile is not an offline one, that a credential is actually
reachable without a terminal, and whether the profile applies to the grid or
only stages the file.

The units it writes:

- `/etc/systemd/system/nexus.service` — `Type=oneshot`, replays the profile
  with `--yes`, waits for routable networking, reads credentials from
  `/opt/nexus/nexus.env` if that file exists.
- `/etc/systemd/system/nexus.timer` — your chosen `OnCalendar`, a randomised
  delay so a fleet does not hit the platform on the same second, and
  `Persistent=true` so a manager that was down still gets its build.

Put the credentials somewhere the timer can read them:

```
sudo tee /opt/nexus/nexus.env >/dev/null <<'ENV'
NEXUS_TOKEN=...
ENV
sudo chmod 600 /opt/nexus/nexus.env
```

Then start it:

```
sudo systemctl daemon-reload
sudo systemctl enable --now nexus.timer
```

Check on it:

```
systemctl list-timers nexus.timer
journalctl -u nexus.service
```

Run one now without waiting:

```
sudo systemctl start nexus.service
```

Remove it:

```
sudo systemctl disable --now nexus.timer
sudo rm /etc/systemd/system/nexus.timer /etc/systemd/system/nexus.service
sudo systemctl daemon-reload
```

---

## Did it work?

After an apply, a matching indicator writes a line to `/nsm/zeek/logs/current/intel.log`.
A malformed intel file is reported in `/nsm/zeek/logs/current/reporter.log`
rather than failing the apply, so that is the first place to look if the file
loaded but nothing matches.

---

## What it will not do

- It will not remove an indicator. The merge is append-only, and a build that
  computes a removal is treated as a bug: it blocks the write rather than
  asking.
- It will not write a broad indicator that would arm Zeek against half the
  internet. Subnets wider than the configured floor are refused.
- It will not let a filter silently match nothing.
- It will not add a dependency.

---

## Tests

```
python3 -m unittest test_nexus
```

No network, no Security Onion, no platform. The suite stands up fake MISP,
OpenCTI and TAXII servers on local sockets.

---

## Status

Working against fake servers and a full offline test suite. **Not yet verified
against a live MISP, OpenCTI or TAXII instance, or a real Security Onion
manager.** `HANDOFF.md` §7 lists exactly what is unverified and what to check
the first time a real one is available.
