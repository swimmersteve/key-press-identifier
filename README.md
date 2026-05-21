# KeyIdentifier

> **Purpose: troubleshooting only.**
> This tool exists to diagnose **spamming / phantom keypresses** — situations where a key (or keys) appears to be typed repeatedly on a Windows machine when no one is actually pressing it. It tells you *where* each keystroke is coming from so you can isolate the cause: a stuck physical key, a misbehaving external keyboard, or a software application that is injecting keystrokes into the OS.
>
> It is **not** a keylogger, monitoring tool, or surveillance utility. It should only be run on a machine you own (or are authorized to troubleshoot), with the awareness of anyone using that machine. When the investigation is complete, stop the tool and delete the log file.

## What it does

When you have a "keys spamming on their own" problem on Windows, you usually don't know whether to blame:

1. The built-in laptop keyboard (stuck/dirty switch).
2. An external USB or Bluetooth keyboard (faulty hardware, dying batteries, wireless interference).
3. A software application that's injecting keystrokes (`SendInput`, `SendKeys`, AutoHotkey, remote-desktop, password manager, vendor utility, malware).

KeyIdentifier runs two independent Windows input pipelines side-by-side and labels every keystroke with its actual source:

| Pipeline | Windows API | What it sees | What you learn |
|---|---|---|---|
| **Physical** | Raw Input (`WM_INPUT`) | Real HID-device keypresses only | **Which keyboard** — device name, VID:PID, USB or Bluetooth |
| **Injected** | Low-level hook (`WH_KEYBOARD_LL` + `LLKHF_INJECTED`) | Software-generated keypresses only | **Which application** — foreground window, owning process, suspect list, injector signature |

So when the spamming starts, the log shows you whether the source is a piece of hardware or a piece of software — and gives you enough information to narrow it further.

## Build

Requires only the in-box .NET Framework 4 compiler that ships with every supported version of Windows. No .NET SDK install needed.

```cmd
build.cmd
```

Produces `KeyIdentifier.exe` (~25 KB).

## Run

```cmd
KeyIdentifier.exe                              :: live log to ./keyidentifier-<ts>.log
KeyIdentifier.exe --log C:\path\to\out.ndjson  :: custom log path
KeyIdentifier.exe --list-devices               :: enumerate attached keyboards and exit
KeyIdentifier.exe --suspect-list               :: list running injection candidates and exit
KeyIdentifier.exe --no-color                   :: plain console output
```

Press **Ctrl+C** to stop. Run from an **elevated** terminal ("Run as administrator") for the cleanest output — without it, integrity-level queries for some processes return `unknown`.

The tool writes both a colored live console feed and an NDJSON log file (one event per line). The console is for watching in real time when the spamming happens; the NDJSON is for post-incident review with `findstr`, `Select-String`, or `jq`.

## Sample output

A real physical key from a Bluetooth Logitech keyboard:

```
[19:57:58.963] PHYSICAL DOWN  vk=0x58 'X'         device: HID Keyboard Device (046D:B019)
[19:57:58.976] PHYSICAL UP    vk=0x58 'X'         device: HID Keyboard Device (046D:B019)
```

A software-injected key (in this example, an AutoHotkey script):

```
[19:58:02.144] INJECTED DOWN  vk=0x41 'A'         source: AutoHotkey (Send/SendInput)
    Foreground : Untitled - Notepad
    Process    : C:\Windows\System32\notepad.exe (pid 12345, integrity Medium)
    Marker     : AutoHotkey (Send/SendInput)
    Suspects   : AutoHotkey64(9876), TabTip(5460)
```

## Why every keypress produces two log lines

Every single press of a key generates **two events** in the log — one when the key goes down, one when it comes back up. Look at the second column:

```
[19:57:58.963] PHYSICAL DOWN  vk=0x58 'X'  device: HID Keyboard Device (046D:B019)
[19:57:58.976] PHYSICAL UP    vk=0x58 'X'  device: HID Keyboard Device (046D:B019)
```

This is how Windows reports keyboard input at every level (Raw Input, low-level hook, message queue) and the tool preserves it intentionally — for spamming-key diagnosis, the DOWN/UP pattern is informative on its own:

- **A normal press** produces one DOWN and one UP, close together in time.
- **A stuck physical key** produces a steady stream of DOWN events with no matching UPs (or, rarely, a missing DOWN with the UP firing repeatedly). This is the signature of a key that the firmware/HID stack thinks is being held.
- **Auto-repeat** (holding a key down) produces multiple DOWN events with no UP in between, followed by a single UP when you release. That's normal keyboard behavior, not a fault.
- **A software macro** typically produces clean DOWN/UP pairs for each emitted key, often unnaturally evenly spaced.

If you would rather only see the DOWN events (halves the log size), open an issue and I'll add a `--down-only` flag — it is a one-line change.

### "I'm seeing two DOWN events for one press, from different `deviceHandle` values"

That is a different situation and not an artifact of the tool. Some keyboards (especially built-in laptop keyboards on certain firmware) are reported through both their native HID path **and** the Windows `ConvertedDevice` legacy compatibility path. Each press generates one event from each, with different device handles. The two paths are mentioned in the Limitations section below; the cleanest fix is to ignore the `ConvertedDevice` entry during diagnosis and focus on the native device.

## How to use it to diagnose spamming keys

1. **Run `--list-devices` once** before the spamming starts. This shows you the baseline of every keyboard currently attached. Note the friendly name and VID:PID of each. The Standard PS/2 entry (path beginning `ACPI#`) is the built-in laptop keyboard; any `HID` entry with a VID/PID is an external device.

2. **Start the tool** with no arguments and leave it running.

3. **Wait for the spamming to happen**, or trigger it if it's reproducible.

4. **Open the log** and find the burst of events around the time of the incident. Read the source label on each event.

### Diagnosis flowchart

- **All events in the burst say `PHYSICAL`?** A keyboard is producing the keys. Look at the `device:` field:
  - If it's always the same device handle, that's the culprit. Compare against your `--list-devices` baseline to identify it.
  - **Disconnect or disable that device** (unplug the USB, turn off the Bluetooth keyboard, or disable the built-in keyboard in Device Manager) and re-test. If the spamming stops, you've found it. Usually this is a stuck/dirty key switch — try compressed air, cleaning, or replacement.
  - If it's the `ConvertedDevice` entry, see the limitations section below.

- **All events in the burst say `INJECTED`?** Software is producing the keys. Look at:
  - **`Marker`** — if set, the injecting application tagged the keystroke with a known signature. AutoHotkey is the most common case (`0xC2C2C2C2`). This is essentially a confirmed identification.
  - **`Foreground`** — this is the window that *received* the key, not the one that *sent* it. Still useful: phantom keys typed into your terminal vs. a hidden background window suggest very different stories.
  - **`Suspects`** — a snapshot of known keystroke-injecting applications that were running at the time. Quit them one at a time and re-test to isolate.
  - Common benign injectors you can usually rule out first: `osk.exe` and `TabTip.exe` (Windows on-screen keyboards), `TextInputHost.exe` (Windows input host), password managers auto-filling, vendor utilities (Logi, Razer, SteelSeries, Corsair).
  - Common non-benign sources: AutoHotkey scripts running from a previous session, remote-desktop tools (`TeamViewer`, `AnyDesk`, `Parsec`, `mstsc.exe`), and macro utilities.

- **Mix of physical and injected events?** Both a hardware and a software source are active. Diagnose them separately.

- **`dwExtraInfo` is non-zero but `Marker` is null?** The injecting process tagged the keystroke with custom data the tool doesn't recognize. The fact that it tagged anything at all is itself suspicious — most legitimate apps pass `0`. Treat the foreground/suspect list as the strongest leads.

## Limitations

- **Per-PID attribution of injected keystrokes is not exposed by Windows.** This tool narrows it down by heuristic (foreground window + suspect catalog + `dwExtraInfo` signature) but does not give a definitive PID for the injecting process. Exact PID attribution would require ETW tracing of the `Microsoft-Windows-Win32k` provider — out of scope here.
- **A jammed/stuck physical key** looks just like an intentional press to Raw Input — same device handle, same vk. The clue is repetition: a steady stream of `WM_KEYDOWN` for one vk while no one is touching the keyboard.
- **Kernel-mode injectors** (some drivers, vendor utilities, rootkits) can place keystrokes into the input stream below the Raw Input layer. Those appear as PHYSICAL events under the `ConvertedDevice` keyboard. If all your phantom keys are attributed to `ConvertedDevice` and no other diagnosis fits, investigate recently installed drivers and vendor utilities that include kernel components.
- **Console title encoding**: on PowerShell 5.1, foreground window titles with non-ASCII characters render mojibake in the live console feed. The NDJSON log file itself is UTF-8 and correct.

## Privacy and responsible use

This tool logs every keystroke the OS sees, including the key, timestamp, foreground window title, and (for injected events) the owning process. **Treat the log file as sensitive.**

- Run it only on machines you own or are explicitly authorized to troubleshoot.
- If other people use the machine, inform them before running it.
- Delete the log file when the investigation is complete.
- Do not share the log externally without redacting sensitive content (titles, key sequences).

Running a low-level keyboard hook does not require Administrator on Windows, but Administrator is required for the tool to read integrity levels of elevated processes. Either way, this is a diagnostic utility — it does not block, modify, or transmit keystrokes anywhere.
