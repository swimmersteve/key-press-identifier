// KeyIdentifier — identify the source of every keystroke on a Windows machine.
//
// Two pipelines run side-by-side on the main thread:
//
//   1. Raw Input (WM_INPUT) — fires only for real HID device events. Each
//      event carries the source device handle, so we can name the keyboard
//      (built-in laptop keyboard, USB Logitech, Bluetooth, etc.).
//      Software-injected keys do NOT appear here.
//
//   2. Low-level keyboard hook (WH_KEYBOARD_LL) — fires for every key,
//      including injected ones. We only log events with the LLKHF_INJECTED
//      flag (anything else is already covered by Raw Input).
//
// Output cleanly labels every event PHYSICAL <device> or INJECTED <suspect>.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace KeyIdentifier
{
    internal enum EventSource { Physical, Injected }

    internal sealed class KeyEvent
    {
        public DateTime TimestampUtc;
        public EventSource Source;
        public uint VkCode;
        public uint ScanCode;
        public bool IsKeyDown;
        public uint Flags;          // hook flags (only for Injected)
        public IntPtr DwExtraInfo;  // hook extra info (sometimes signals injector identity)

        // Raw Input (Physical) attribution
        public IntPtr DeviceHandle;
        public string DevicePath;
        public string DeviceFriendlyName;
        public string DeviceVendorId;
        public string DeviceProductId;

        // Hook (Injected) attribution
        public IntPtr ForegroundHwnd;
        public string ForegroundTitle;
        public int ForegroundPid;
        public string ForegroundExe;
        public string ForegroundIntegrity;
        public List<SuspectProcess> Suspects;
        public string KnownInjectorMarker;  // e.g., "AutoHotkey" if dwExtraInfo matches a known signature
    }

    internal sealed class SuspectProcess
    {
        public int Pid;
        public string Name;
        public string ExePath;
    }

    internal static class Program
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int HC_ACTION = 0;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int WM_QUIT = 0x0012;
        private const int WM_INPUT = 0x00FF;
        private const int WM_DESTROY = 0x0002;
        private const uint LLKHF_INJECTED = 0x10;

        private static NativeMethods.LowLevelKeyboardProc s_hookDelegate;
        private static NativeMethods.WndProc s_wndProcDelegate;
        private static IntPtr s_hookHandle = IntPtr.Zero;
        private static IntPtr s_msgWindow = IntPtr.Zero;
        private static uint s_mainThreadId;

        private static BlockingCollection<KeyEvent> s_queue = new BlockingCollection<KeyEvent>(boundedCapacity: 8192);
        private static LogWriter s_log;
        private static bool s_useColor = true;

        private static int Main(string[] args)
        {
            string logPath = null;
            bool listDevicesOnly = false;
            bool suspectListOnly = false;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--log":
                        if (i + 1 >= args.Length) { Console.Error.WriteLine("--log requires a path"); return 2; }
                        logPath = args[++i];
                        break;
                    case "--no-color":
                        s_useColor = false;
                        break;
                    case "--list-devices":
                        listDevicesOnly = true;
                        break;
                    case "--suspect-list":
                        suspectListOnly = true;
                        break;
                    case "-h":
                    case "--help":
                        PrintHelp();
                        return 0;
                    default:
                        Console.Error.WriteLine("unknown argument: " + args[i]);
                        PrintHelp();
                        return 2;
                }
            }

            if (listDevicesOnly) { DumpDevicesAndExit(); return 0; }
            if (suspectListOnly) { DumpSuspectsAndExit(); return 0; }

            if (logPath == null)
                logPath = "keyidentifier-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".log";

            s_log = new LogWriter(logPath, s_useColor);
            s_log.WriteBanner(logPath);
            s_log.WriteAttachedKeyboards(DeviceResolver.ListKeyboards());

            var worker = new Thread(WorkerLoop) { IsBackground = true, Name = "ki-worker" };
            worker.Start();

            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                NativeMethods.PostThreadMessage(s_mainThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero);
            };

            s_mainThreadId = NativeMethods.GetCurrentThreadId();

            // 1) Message-only window for WM_INPUT (Raw Input).
            if (!CreateMessageWindow())
            {
                Console.Error.WriteLine("Failed to create message window: " + Marshal.GetLastWin32Error());
                return 1;
            }

            // 2) Register for raw keyboard input from any thread (RIDEV_INPUTSINK).
            if (!RegisterRawKeyboard())
            {
                Console.Error.WriteLine("RegisterRawInputDevices failed: " + Marshal.GetLastWin32Error());
                return 1;
            }

            // 3) Install low-level keyboard hook (only logs injected events).
            s_hookDelegate = HookCallback;
            IntPtr hMod = NativeMethods.GetModuleHandle(null);
            s_hookHandle = NativeMethods.SetWindowsHookEx(WH_KEYBOARD_LL, s_hookDelegate, hMod, 0);
            if (s_hookHandle == IntPtr.Zero)
            {
                Console.Error.WriteLine("SetWindowsHookEx failed: " + Marshal.GetLastWin32Error());
                return 1;
            }

            try
            {
                NativeMethods.MSG msg;
                int ret;
                while ((ret = NativeMethods.GetMessage(out msg, IntPtr.Zero, 0, 0)) != 0)
                {
                    if (ret == -1) break;
                    NativeMethods.TranslateMessage(ref msg);
                    NativeMethods.DispatchMessage(ref msg);
                }
            }
            finally
            {
                if (s_hookHandle != IntPtr.Zero) NativeMethods.UnhookWindowsHookEx(s_hookHandle);
                if (s_msgWindow != IntPtr.Zero) NativeMethods.DestroyWindow(s_msgWindow);
                s_queue.CompleteAdding();
                worker.Join(2000);
                s_log.Close();
            }
            return 0;
        }

        private static void PrintHelp()
        {
            Console.WriteLine("KeyIdentifier — identify the source of every keystroke");
            Console.WriteLine();
            Console.WriteLine("Usage: KeyIdentifier.exe [options]");
            Console.WriteLine("  --log <path>      Write NDJSON log to <path>  (default: ./keyidentifier-<ts>.log)");
            Console.WriteLine("  --list-devices    List all attached keyboards and exit");
            Console.WriteLine("  --suspect-list    List running keystroke-injector candidates and exit");
            Console.WriteLine("  --no-color        Disable colored console output");
            Console.WriteLine("  -h, --help        Show this help");
            Console.WriteLine();
            Console.WriteLine("Every keystroke is labeled:");
            Console.WriteLine("  PHYSICAL  <device name (VID:PID)>      — from a real HID keyboard");
            Console.WriteLine("  INJECTED  <suspect process / window>   — generated by software");
            Console.WriteLine();
            Console.WriteLine("Press Ctrl+C to stop.");
        }

        // -------------------- message window for raw input --------------------

        private const string WND_CLASS = "KeyIdentifier_MsgOnly";

        private static bool CreateMessageWindow()
        {
            s_wndProcDelegate = WindowProc;
            IntPtr hInst = NativeMethods.GetModuleHandle(null);

            var wc = new NativeMethods.WNDCLASSEX();
            wc.cbSize = Marshal.SizeOf(typeof(NativeMethods.WNDCLASSEX));
            wc.lpfnWndProc = s_wndProcDelegate;
            wc.hInstance = hInst;
            wc.lpszClassName = WND_CLASS;
            ushort atom = NativeMethods.RegisterClassEx(ref wc);
            if (atom == 0)
            {
                int err = Marshal.GetLastWin32Error();
                if (err != 1410 /* ERROR_CLASS_ALREADY_EXISTS */) return false;
            }
            // HWND_MESSAGE = -3 → creates a message-only window (no UI, but receives messages)
            s_msgWindow = NativeMethods.CreateWindowEx(0, WND_CLASS, "KeyIdentifier", 0, 0, 0, 0, 0,
                new IntPtr(-3), IntPtr.Zero, hInst, IntPtr.Zero);
            return s_msgWindow != IntPtr.Zero;
        }

        private static bool RegisterRawKeyboard()
        {
            var rid = new NativeMethods.RAWINPUTDEVICE
            {
                usUsagePage = 0x01,   // Generic desktop
                usUsage = 0x06,       // Keyboard
                dwFlags = 0x00000100, // RIDEV_INPUTSINK — receive events even when not focused
                hwndTarget = s_msgWindow,
            };
            return NativeMethods.RegisterRawInputDevices(new[] { rid }, 1, (uint)Marshal.SizeOf(typeof(NativeMethods.RAWINPUTDEVICE)));
        }

        private static IntPtr WindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            if (msg == WM_INPUT)
            {
                HandleRawInput(lParam);
                return IntPtr.Zero;
            }
            if (msg == WM_DESTROY) { return IntPtr.Zero; }
            return NativeMethods.DefWindowProc(hWnd, msg, wParam, lParam);
        }

        private static void HandleRawInput(IntPtr hRawInput)
        {
            uint size = 0;
            uint headerSize = (uint)Marshal.SizeOf(typeof(NativeMethods.RAWINPUTHEADER));
            uint rc = NativeMethods.GetRawInputData(hRawInput, 0x10000003 /*RID_INPUT*/, IntPtr.Zero, ref size, headerSize);
            if (rc != 0 || size == 0) return;

            IntPtr buf = Marshal.AllocHGlobal((int)size);
            try
            {
                uint copied = NativeMethods.GetRawInputData(hRawInput, 0x10000003, buf, ref size, headerSize);
                if (copied == uint.MaxValue) return;

                var hdr = (NativeMethods.RAWINPUTHEADER)Marshal.PtrToStructure(buf, typeof(NativeMethods.RAWINPUTHEADER));
                if (hdr.dwType != 1 /*RIM_TYPEKEYBOARD*/) return;

                // Raw Input emits events for synthetic input too, but with hDevice == 0.
                // The low-level hook captures those (with the INJECTED flag) — skip here
                // to avoid double-reporting.
                if (hdr.hDevice == IntPtr.Zero) return;

                var kb = (NativeMethods.RAWKEYBOARD)Marshal.PtrToStructure(
                    new IntPtr(buf.ToInt64() + headerSize), typeof(NativeMethods.RAWKEYBOARD));

                // Filter out the "fake key" Windows sometimes injects for some HID layouts
                if (kb.VKey == 0xFF) return;

                bool isDown = (kb.Flags & 0x01) == 0;  // RI_KEY_BREAK = 0x01 → key up

                var ev = new KeyEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Source = EventSource.Physical,
                    VkCode = kb.VKey,
                    ScanCode = kb.MakeCode,
                    IsKeyDown = isDown,
                    DeviceHandle = hdr.hDevice,
                };
                s_queue.TryAdd(ev);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // -------------------- low-level hook (injection detection) --------------------

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode == HC_ACTION)
            {
                var data = (NativeMethods.KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(NativeMethods.KBDLLHOOKSTRUCT));
                bool injected = (data.flags & LLKHF_INJECTED) != 0;
                if (injected)
                {
                    int msg = wParam.ToInt32();
                    bool isDown = (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN);
                    var ev = new KeyEvent
                    {
                        TimestampUtc = DateTime.UtcNow,
                        Source = EventSource.Injected,
                        VkCode = data.vkCode,
                        ScanCode = data.scanCode,
                        Flags = data.flags,
                        DwExtraInfo = data.dwExtraInfo,
                        IsKeyDown = isDown,
                        ForegroundHwnd = NativeMethods.GetForegroundWindow(),
                    };
                    s_queue.TryAdd(ev);
                }
            }
            return NativeMethods.CallNextHookEx(s_hookHandle, nCode, wParam, lParam);
        }

        // -------------------- worker loop --------------------

        private static void WorkerLoop()
        {
            var enricher = new Enricher();
            try
            {
                foreach (var ev in s_queue.GetConsumingEnumerable())
                {
                    try { enricher.Enrich(ev); s_log.Write(ev); }
                    catch (Exception ex) { Console.Error.WriteLine("worker error: " + ex.Message); }
                }
            }
            catch (InvalidOperationException) { /* completed */ }
        }

        private static void DumpDevicesAndExit()
        {
            Console.WriteLine("Attached keyboard devices (RIM_TYPEKEYBOARD):");
            Console.WriteLine();
            var kbs = DeviceResolver.ListKeyboards();
            int i = 1;
            foreach (var k in kbs)
            {
                Console.WriteLine("  [{0}] {1}", i++, k.FriendlyName ?? "(unnamed)");
                Console.WriteLine("      VID:PID    : {0}:{1}", k.VendorId ?? "????", k.ProductId ?? "????");
                Console.WriteLine("      Handle     : 0x{0:X}", k.Handle.ToInt64());
                Console.WriteLine("      Device path: {0}", k.DevicePath);
                Console.WriteLine();
            }
            Console.WriteLine("Total: {0}", kbs.Count);
        }

        private static void DumpSuspectsAndExit()
        {
            Console.WriteLine("Scanning processes for known keystroke-injection sources...");
            Console.WriteLine();
            var s = SuspectScanner.Scan();
            if (s.Count == 0) { Console.WriteLine("  (none matched)"); return; }
            foreach (var p in s)
                Console.WriteLine("  [{0,5}] {1,-32} {2}", p.Pid, p.Name, p.ExePath ?? "(path unavailable)");
            Console.WriteLine();
            Console.WriteLine("Total: {0}", s.Count);
        }
    }

    // ========================= enricher =========================

    internal sealed class Enricher
    {
        private DateTime _lastSuspectScan = DateTime.MinValue;
        private List<SuspectProcess> _cachedSuspects = new List<SuspectProcess>();
        private readonly Dictionary<IntPtr, DeviceInfo> _deviceCache = new Dictionary<IntPtr, DeviceInfo>();

        public void Enrich(KeyEvent ev)
        {
            if (ev.Source == EventSource.Physical)
            {
                DeviceInfo info;
                if (!_deviceCache.TryGetValue(ev.DeviceHandle, out info))
                {
                    info = DeviceResolver.Resolve(ev.DeviceHandle);
                    _deviceCache[ev.DeviceHandle] = info;
                }
                if (info != null)
                {
                    ev.DevicePath = info.DevicePath;
                    ev.DeviceFriendlyName = info.FriendlyName;
                    ev.DeviceVendorId = info.VendorId;
                    ev.DeviceProductId = info.ProductId;
                }
                return;
            }

            // Injected: foreground window + process + integrity + known marker + suspect snapshot.
            if (ev.ForegroundHwnd != IntPtr.Zero)
            {
                var sb = new StringBuilder(512);
                NativeMethods.GetWindowText(ev.ForegroundHwnd, sb, sb.Capacity);
                ev.ForegroundTitle = sb.ToString();

                uint pid;
                NativeMethods.GetWindowThreadProcessId(ev.ForegroundHwnd, out pid);
                ev.ForegroundPid = (int)pid;
                if (pid != 0)
                {
                    try
                    {
                        using (var p = Process.GetProcessById((int)pid))
                        {
                            try { ev.ForegroundExe = p.MainModule != null ? p.MainModule.FileName : null; }
                            catch { ev.ForegroundExe = p.ProcessName + ".exe"; }
                        }
                    }
                    catch { }
                    ev.ForegroundIntegrity = IntegrityLevel.For((int)pid);
                }
            }

            ev.KnownInjectorMarker = KnownInjectors.Identify(ev.DwExtraInfo);

            var now = DateTime.UtcNow;
            if ((now - _lastSuspectScan).TotalSeconds > 60)
            {
                _cachedSuspects = SuspectScanner.Scan();
                _lastSuspectScan = now;
            }
            ev.Suspects = _cachedSuspects;
        }
    }

    // ========================= known injector signatures =========================

    internal static class KnownInjectors
    {
        // Some injectors put recognizable values in INPUT.ki.dwExtraInfo that survive
        // through to KBDLLHOOKSTRUCT.dwExtraInfo. This is best-effort attribution.
        public static string Identify(IntPtr extraInfo)
        {
            long v = extraInfo.ToInt64() & 0xFFFFFFFFL;
            if (v == 0) return null;
            if (v == 0xC2C2C2C2) return "AutoHotkey (Send/SendInput)";
            if (v == 0xD2D2D2D2) return "AutoHotkey (SendPlay)";
            if (v == 0xCACACACA) return "AutoHotkey (custom)";
            // Generic non-zero: at least signals that the injector tagged it.
            return "tagged (0x" + v.ToString("X") + ")";
        }
    }

    // ========================= device resolver =========================

    internal sealed class DeviceInfo
    {
        public IntPtr Handle;
        public string DevicePath;
        public string FriendlyName;
        public string VendorId;
        public string ProductId;
    }

    internal static class DeviceResolver
    {
        private const uint RIDI_DEVICENAME = 0x20000007;
        private const uint RIDI_DEVICEINFO = 0x2000000b;
        private const uint RIM_TYPEKEYBOARD = 1;

        // Resolve a device handle from a raw input event to (path, friendly name, VID, PID).
        public static DeviceInfo Resolve(IntPtr hDevice)
        {
            if (hDevice == IntPtr.Zero) return new DeviceInfo { FriendlyName = "(no device handle — likely synthetic)" };
            string path = GetDeviceName(hDevice);
            if (string.IsNullOrEmpty(path)) return new DeviceInfo { Handle = hDevice, FriendlyName = "(unresolved handle)" };

            string vid, pid;
            ParseVidPid(path, out vid, out pid);
            string friendly = LookupFriendlyName(path) ?? FallbackName(path);

            return new DeviceInfo
            {
                Handle = hDevice,
                DevicePath = path,
                FriendlyName = friendly,
                VendorId = vid,
                ProductId = pid,
            };
        }

        // Enumerate all currently-attached keyboards.
        public static List<DeviceInfo> ListKeyboards()
        {
            var result = new List<DeviceInfo>();
            uint count = 0;
            uint size = (uint)Marshal.SizeOf(typeof(NativeMethods.RAWINPUTDEVICELIST));
            if (NativeMethods.GetRawInputDeviceList(IntPtr.Zero, ref count, size) != 0) return result;
            if (count == 0) return result;

            IntPtr arr = Marshal.AllocHGlobal((int)(count * size));
            try
            {
                if (NativeMethods.GetRawInputDeviceList(arr, ref count, size) == uint.MaxValue) return result;
                for (int i = 0; i < count; i++)
                {
                    IntPtr p = new IntPtr(arr.ToInt64() + i * size);
                    var entry = (NativeMethods.RAWINPUTDEVICELIST)Marshal.PtrToStructure(p, typeof(NativeMethods.RAWINPUTDEVICELIST));
                    if (entry.dwType != RIM_TYPEKEYBOARD) continue;
                    var info = Resolve(entry.hDevice);
                    if (info != null) result.Add(info);
                }
            }
            finally { Marshal.FreeHGlobal(arr); }
            return result;
        }

        private static string GetDeviceName(IntPtr hDevice)
        {
            uint size = 0;
            NativeMethods.GetRawInputDeviceInfo(hDevice, RIDI_DEVICENAME, IntPtr.Zero, ref size);
            if (size == 0) return null;
            IntPtr buf = Marshal.AllocHGlobal((int)size * 2);
            try
            {
                if (NativeMethods.GetRawInputDeviceInfo(hDevice, RIDI_DEVICENAME, buf, ref size) == uint.MaxValue)
                    return null;
                return Marshal.PtrToStringAuto(buf);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // USB:       ...VID_046D&PID_C541...
        // Bluetooth: ...VID&02046D_PID&B019...   (the 2-char prefix is a source ID)
        private static readonly Regex VidPidRegex = new Regex(
            @"VID[_&](?:[0-9A-Fa-f]{2})?([0-9A-Fa-f]{4})[\s\S]*?PID[_&]([0-9A-Fa-f]{4})",
            RegexOptions.Compiled);

        private static void ParseVidPid(string path, out string vid, out string pid)
        {
            vid = null; pid = null;
            if (string.IsNullOrEmpty(path)) return;
            var m = VidPidRegex.Match(path);
            if (m.Success)
            {
                vid = m.Groups[1].Value.ToUpperInvariant();
                pid = m.Groups[2].Value.ToUpperInvariant();
            }
        }

        // Device path looks like: \\?\HID#VID_046D&PID_C541&MI_01&Col01#7&1a2b3c4d&0&0000#{884b96c3-...}
        // Registry key:           HKLM\SYSTEM\CurrentControlSet\Enum\HID\VID_046D&PID_C541&MI_01&Col01\7&1a2b3c4d&0&0000
        private static string LookupFriendlyName(string devicePath)
        {
            if (string.IsNullOrEmpty(devicePath)) return null;
            string p = devicePath;
            if (p.StartsWith("\\\\?\\")) p = p.Substring(4);

            int guidStart = p.LastIndexOf("#{");
            if (guidStart > 0) p = p.Substring(0, guidStart);

            // p is now: HID#VID_046D&PID_C541&MI_01&Col01#7&1a2b3c4d&0&0000
            string regKey = "SYSTEM\\CurrentControlSet\\Enum\\" + p.Replace('#', '\\');
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(regKey))
                {
                    if (key == null) return null;
                    string friendly = key.GetValue("FriendlyName") as string;
                    if (!string.IsNullOrEmpty(friendly)) return CleanDeviceDesc(friendly);
                    string desc = key.GetValue("DeviceDesc") as string;
                    if (!string.IsNullOrEmpty(desc)) return CleanDeviceDesc(desc);
                }
            }
            catch { }
            return null;
        }

        // DeviceDesc often looks like: @oem8.inf,%hid_device_system_keyboard%;HID Keyboard Device
        // We want the friendly part after the last ';'.
        private static string CleanDeviceDesc(string desc)
        {
            int semi = desc.LastIndexOf(';');
            if (semi >= 0 && semi < desc.Length - 1) return desc.Substring(semi + 1).Trim();
            return desc.Trim();
        }

        private static string FallbackName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "(unknown)";
            if (path.IndexOf("RDP_", StringComparison.OrdinalIgnoreCase) >= 0) return "RDP virtual keyboard";
            if (path.IndexOf("ROOT", StringComparison.OrdinalIgnoreCase) >= 0) return "system-virtual keyboard";
            if (path.IndexOf("HID", StringComparison.OrdinalIgnoreCase) >= 0) return "HID keyboard";
            return "(unresolved)";
        }
    }

    // ========================= suspect process scan =========================

    internal static class SuspectScanner
    {
        private static readonly string[] Patterns = new[]
        {
            "autohotkey", "ahk", "nircmd", "xdotool", "pulover",
            "osk.exe", "tabtip", "textinputhost",
            "mstsc", "rdpclip", "teamviewer", "anydesk", "vncserver",
            "tvnserver", "winvnc", "parsec", "splashtop", "remotedesktop",
            "logmein", "gotomeeting", "screenconnect", "connectwise",
            "1password", "bitwarden", "lastpass", "keepass", "dashlane", "roboform",
            "streamdeck", "loupedeck", "razer", "logi", "ghub", "synapse",
            "steelseries", "icue", "corsair", "ducky", "wooting",
            "macro", "auto-typer", "autotyper", "remap", "hotkey",
            "keystroke", "injector",
        };

        public static List<SuspectProcess> Scan()
        {
            var results = new List<SuspectProcess>();
            Process[] procs;
            try { procs = Process.GetProcesses(); } catch { return results; }
            foreach (var p in procs)
            {
                try
                {
                    string name = p.ProcessName ?? "";
                    string path = null;
                    try { if (p.MainModule != null) path = p.MainModule.FileName; } catch { }
                    string needle = (name + "|" + (path ?? "")).ToLowerInvariant();
                    for (int i = 0; i < Patterns.Length; i++)
                    {
                        if (needle.IndexOf(Patterns[i], StringComparison.Ordinal) >= 0)
                        {
                            results.Add(new SuspectProcess { Pid = p.Id, Name = name, ExePath = path });
                            break;
                        }
                    }
                }
                catch { }
                finally { try { p.Dispose(); } catch { } }
            }
            return results;
        }
    }

    // ========================= integrity level =========================

    internal static class IntegrityLevel
    {
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenIntegrityLevel = 25;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public static string For(int pid)
        {
            IntPtr hProc = NativeMethods.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (hProc == IntPtr.Zero) return "unknown";
            try
            {
                IntPtr hTok;
                if (!NativeMethods.OpenProcessToken(hProc, TOKEN_QUERY, out hTok)) return "unknown";
                try
                {
                    uint needed;
                    NativeMethods.GetTokenInformation(hTok, TokenIntegrityLevel, IntPtr.Zero, 0, out needed);
                    if (needed == 0) return "unknown";
                    IntPtr buf = Marshal.AllocHGlobal((int)needed);
                    try
                    {
                        if (!NativeMethods.GetTokenInformation(hTok, TokenIntegrityLevel, buf, needed, out needed))
                            return "unknown";
                        IntPtr pSid = Marshal.ReadIntPtr(buf, 0);
                        int subAuthCount = Marshal.ReadByte(pSid, 1);
                        int rid = Marshal.ReadInt32(pSid, 8 + 4 * (subAuthCount - 1));
                        if (rid < 0x1000) return "Untrusted";
                        if (rid < 0x2000) return "Low";
                        if (rid < 0x3000) return "Medium";
                        if (rid < 0x3100) return "MediumPlus";
                        if (rid < 0x4000) return "High";
                        return "System";
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
                finally { NativeMethods.CloseHandle(hTok); }
            }
            finally { NativeMethods.CloseHandle(hProc); }
        }
    }

    // ========================= log writer =========================

    internal sealed class LogWriter : IDisposable
    {
        private readonly StreamWriter _file;
        private readonly bool _color;
        private readonly object _lock = new object();

        public LogWriter(string path, bool color)
        {
            _file = new StreamWriter(path, append: false, encoding: new UTF8Encoding(false));
            _file.AutoFlush = true;
            _color = color;
        }

        public void WriteBanner(string logPath)
        {
            Console.WriteLine("KeyIdentifier — logging to: " + logPath);
            Console.WriteLine("Press Ctrl+C to stop.");
            Console.WriteLine(new string('-', 78));
        }

        public void WriteAttachedKeyboards(List<DeviceInfo> kbs)
        {
            Console.WriteLine("Attached keyboards at startup:");
            int i = 1;
            foreach (var k in kbs)
                Console.WriteLine("  [{0}] {1} ({2}:{3})", i++,
                    k.FriendlyName ?? "(unnamed)",
                    k.VendorId ?? "????", k.ProductId ?? "????");
            Console.WriteLine(new string('-', 78));

            // also emit to the log file for context
            _file.WriteLine("{\"ts\":\"" + DateTime.UtcNow.ToString("o") + "\",\"event\":\"startup\",\"keyboards\":[" +
                string.Join(",", kbs.Select(k =>
                    "{\"name\":" + Json(k.FriendlyName) +
                    ",\"vid\":" + Json(k.VendorId) +
                    ",\"pid\":" + Json(k.ProductId) +
                    ",\"path\":" + Json(k.DevicePath) + "}").ToArray()) + "]}");
        }

        public void Write(KeyEvent ev)
        {
            lock (_lock)
            {
                _file.WriteLine(ToNdjson(ev));
                WriteConsole(ev);
            }
        }

        private void WriteConsole(KeyEvent ev)
        {
            ConsoleColor prev = Console.ForegroundColor;
            if (_color) Console.ForegroundColor = ev.Source == EventSource.Injected ? ConsoleColor.Red : ConsoleColor.Cyan;
            try
            {
                if (ev.Source == EventSource.Physical)
                {
                    Console.WriteLine("[{0}] PHYSICAL {1,-4}  vk=0x{2:X2} {3,-10}  device: {4} ({5}:{6})",
                        ev.TimestampUtc.ToString("HH:mm:ss.fff"),
                        ev.IsKeyDown ? "DOWN" : "UP",
                        ev.VkCode,
                        "'" + KeyName(ev.VkCode) + "'",
                        ev.DeviceFriendlyName ?? "(unknown)",
                        ev.DeviceVendorId ?? "????",
                        ev.DeviceProductId ?? "????");
                }
                else
                {
                    Console.WriteLine("[{0}] INJECTED {1,-4}  vk=0x{2:X2} {3,-10}  source: {4}",
                        ev.TimestampUtc.ToString("HH:mm:ss.fff"),
                        ev.IsKeyDown ? "DOWN" : "UP",
                        ev.VkCode,
                        "'" + KeyName(ev.VkCode) + "'",
                        BestInjectorGuess(ev));
                    Console.WriteLine("    Foreground : {0}", string.IsNullOrEmpty(ev.ForegroundTitle) ? "(no title)" : ev.ForegroundTitle);
                    Console.WriteLine("    Process    : {0} (pid {1}, integrity {2})",
                        ev.ForegroundExe ?? "(unknown)", ev.ForegroundPid, ev.ForegroundIntegrity ?? "unknown");
                    if (ev.KnownInjectorMarker != null)
                        Console.WriteLine("    Marker     : {0}", ev.KnownInjectorMarker);
                    if (ev.Suspects != null && ev.Suspects.Count > 0)
                    {
                        var list = string.Join(", ", ev.Suspects.Select(s => s.Name + "(" + s.Pid + ")").Take(8).ToArray());
                        Console.WriteLine("    Suspects   : {0}{1}", list,
                            ev.Suspects.Count > 8 ? " (+" + (ev.Suspects.Count - 8) + " more)" : "");
                    }
                }
            }
            finally { if (_color) Console.ForegroundColor = prev; }
        }

        private static string BestInjectorGuess(KeyEvent ev)
        {
            if (ev.KnownInjectorMarker != null) return ev.KnownInjectorMarker;
            if (ev.Suspects != null && ev.Suspects.Count == 1) return ev.Suspects[0].Name + " (pid " + ev.Suspects[0].Pid + ")";
            return "unknown (see Foreground / Suspects below)";
        }

        private static string ToNdjson(KeyEvent ev)
        {
            var sb = new StringBuilder(512);
            sb.Append('{');
            sb.Append("\"ts\":").Append(Json(ev.TimestampUtc.ToString("o"))).Append(',');
            sb.Append("\"source\":\"").Append(ev.Source).Append("\",");
            sb.Append("\"isDown\":").Append(ev.IsKeyDown ? "true" : "false").Append(',');
            sb.Append("\"vk\":").Append(ev.VkCode).Append(',');
            sb.Append("\"sc\":").Append(ev.ScanCode).Append(',');
            sb.Append("\"keyName\":").Append(Json(KeyName(ev.VkCode)));

            if (ev.Source == EventSource.Physical)
            {
                sb.Append(',');
                sb.Append("\"deviceHandle\":\"0x").AppendFormat("{0:X}", ev.DeviceHandle.ToInt64()).Append("\",");
                sb.Append("\"deviceName\":").Append(Json(ev.DeviceFriendlyName)).Append(',');
                sb.Append("\"vid\":").Append(Json(ev.DeviceVendorId)).Append(',');
                sb.Append("\"pid\":").Append(Json(ev.DeviceProductId)).Append(',');
                sb.Append("\"devicePath\":").Append(Json(ev.DevicePath));
            }
            else
            {
                sb.Append(',');
                sb.Append("\"flagsRaw\":").Append(ev.Flags).Append(',');
                sb.Append("\"dwExtraInfo\":\"0x").AppendFormat("{0:X}", ev.DwExtraInfo.ToInt64()).Append("\",");
                sb.Append("\"injectorMarker\":").Append(Json(ev.KnownInjectorMarker)).Append(',');
                sb.Append("\"foregroundHwnd\":\"0x").AppendFormat("{0:X8}", ev.ForegroundHwnd.ToInt64()).Append("\",");
                sb.Append("\"foregroundTitle\":").Append(Json(ev.ForegroundTitle)).Append(',');
                sb.Append("\"foregroundPid\":").Append(ev.ForegroundPid).Append(',');
                sb.Append("\"foregroundExe\":").Append(Json(ev.ForegroundExe)).Append(',');
                sb.Append("\"foregroundIntegrity\":").Append(Json(ev.ForegroundIntegrity));
                if (ev.Suspects != null && ev.Suspects.Count > 0)
                {
                    sb.Append(",\"suspects\":[");
                    for (int i = 0; i < ev.Suspects.Count; i++)
                    {
                        if (i > 0) sb.Append(',');
                        var s = ev.Suspects[i];
                        sb.Append("{\"name\":").Append(Json(s.Name))
                          .Append(",\"pid\":").Append(s.Pid)
                          .Append(",\"exe\":").Append(Json(s.ExePath)).Append('}');
                    }
                    sb.Append(']');
                }
            }
            sb.Append('}');
            return sb.ToString();
        }

        internal static string Json(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder(s.Length + 2);
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        private static string KeyName(uint vk)
        {
            switch (vk)
            {
                case 0x08: return "Back";
                case 0x09: return "Tab";
                case 0x0D: return "Enter";
                case 0x10: return "Shift";
                case 0x11: return "Ctrl";
                case 0x12: return "Alt";
                case 0x13: return "Pause";
                case 0x14: return "CapsLock";
                case 0x1B: return "Esc";
                case 0x20: return "Space";
                case 0x21: return "PgUp";
                case 0x22: return "PgDn";
                case 0x23: return "End";
                case 0x24: return "Home";
                case 0x25: return "Left";
                case 0x26: return "Up";
                case 0x27: return "Right";
                case 0x28: return "Down";
                case 0x2C: return "PrtSc";
                case 0x2D: return "Insert";
                case 0x2E: return "Delete";
                case 0x5B: return "LWin";
                case 0x5C: return "RWin";
                case 0x5D: return "Apps";
                case 0xA0: return "LShift";
                case 0xA1: return "RShift";
                case 0xA2: return "LCtrl";
                case 0xA3: return "RCtrl";
                case 0xA4: return "LAlt";
                case 0xA5: return "RAlt";
            }
            if (vk >= 0x30 && vk <= 0x39) return ((char)vk).ToString();
            if (vk >= 0x41 && vk <= 0x5A) return ((char)vk).ToString();
            if (vk >= 0x60 && vk <= 0x69) return "Num" + (vk - 0x60);
            if (vk >= 0x70 && vk <= 0x87) return "F" + (vk - 0x6F);
            uint mapped = NativeMethods.MapVirtualKey(vk, 2) & 0x7FFFFFFF;
            if (mapped != 0 && mapped < 0xFFFF) return ((char)mapped).ToString();
            return "VK_0x" + vk.ToString("X2");
        }

        public void Close() { try { _file.Flush(); _file.Dispose(); } catch { } }
        public void Dispose() { Close(); }
    }

    // ========================= P/Invoke =========================

    internal static class NativeMethods
    {
        public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        public delegate IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        public struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int pt_x;
            public int pt_y;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WNDCLASSEX
        {
            public int cbSize;
            public uint style;
            [MarshalAs(UnmanagedType.FunctionPtr)] public WndProc lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            public string lpszMenuName;
            public string lpszClassName;
            public IntPtr hIconSm;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RAWINPUTDEVICE
        {
            public ushort usUsagePage;
            public ushort usUsage;
            public uint dwFlags;
            public IntPtr hwndTarget;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RAWINPUTHEADER
        {
            public uint dwType;
            public uint dwSize;
            public IntPtr hDevice;
            public IntPtr wParam;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RAWKEYBOARD
        {
            public ushort MakeCode;
            public ushort Flags;
            public ushort Reserved;
            public ushort VKey;
            public uint Message;
            public uint ExtraInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RAWINPUTDEVICELIST
        {
            public IntPtr hDevice;
            public uint dwType;
        }

        // ---- user32 hooks ----
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        // ---- message loop ----
        [DllImport("user32.dll", SetLastError = true)]
        public static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        public static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        public static extern IntPtr DispatchMessage(ref MSG lpMsg);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PostThreadMessage(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);

        // ---- window ----
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ushort RegisterClassEx(ref WNDCLASSEX lpwcx);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateWindowEx(uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
            int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

        [DllImport("user32.dll")]
        public static extern bool DestroyWindow(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr DefWindowProc(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        // ---- raw input ----
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RegisterRawInputDevices([In] RAWINPUTDEVICE[] pRawInputDevices, uint uiNumDevices, uint cbSize);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetRawInputData(IntPtr hRawInput, uint uiCommand, IntPtr pData, ref uint pcbSize, uint cbSizeHeader);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern uint GetRawInputDeviceInfo(IntPtr hDevice, uint uiCommand, IntPtr pData, ref uint pcbSize);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetRawInputDeviceList(IntPtr pRawInputDeviceList, ref uint puiNumDevices, uint cbSize);

        // ---- misc user32 ----
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll")]
        public static extern uint MapVirtualKey(uint uCode, uint uMapType);

        // ---- kernel32 / advapi32 ----
        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
