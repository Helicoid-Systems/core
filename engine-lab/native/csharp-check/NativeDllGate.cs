// NativeDllGate.cs — Windows-only restricted native search path for the C# check.
//
// Forces [DllImport("librustdesk")] resolution to ONE exact DLL file inside
// HS_NATIVE_DLL_DIR. Dependent native libraries are found only through
// explicit owned directories (HS_NATIVE_DEP_DIRS + the DLL's own directory)
// via LoadLibraryExW LOAD_LIBRARY_SEARCH_* flags. Ambient PATH is not searched.
// OS system libraries keep working (System32 stays in the default search set).
//
// GetModuleFileNameW failures and truncation hard-fail. The module path must
// equal the expected exact file path. One owned load per process; the resolver
// never frees the engine handle and never returns a second module.
//
// No mock Session, no fake exports, no ambient fallback.

using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Helicoid.EngineLab.Check
{
    internal static class NativeDllGate
    {
        private const string LibName = "librustdesk";

        // LoadLibraryExW / SetDefaultDllDirectories flags (winbase.h).
        private const uint LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100;
        private const uint LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200;
        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
        private const uint LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400;
        private const uint LOAD_LIBRARY_SEARCH_DEFAULT_DIRS =
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
            LOAD_LIBRARY_SEARCH_SYSTEM32 |
            LOAD_LIBRARY_SEARCH_USER_DIRS;

        private static string _expectedPath;
        private static IntPtr _handle;
        private static bool _loaded;

        [ModuleInitializer]
        internal static void Install()
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "NativeDllGate is a Windows-only helper; refusing a false platform claim.");
            }

            string nativeDir = Environment.GetEnvironmentVariable("HS_NATIVE_DLL_DIR");
            if (string.IsNullOrEmpty(nativeDir))
            {
                string[] args = Environment.GetCommandLineArgs();
                for (int i = 0; i + 1 < args.Length; i++)
                {
                    if (args[i] == "--native-dir")
                    {
                        nativeDir = args[i + 1];
                    }
                }
            }
            if (string.IsNullOrEmpty(nativeDir) || !Directory.Exists(nativeDir))
            {
                throw new InvalidOperationException(
                    "HS_NATIVE_DLL_DIR (or --native-dir) must name the real built DLL directory; " +
                    "ambient process-global native lookup is refused.");
            }
            nativeDir = Path.GetFullPath(nativeDir);
            string expected = Path.Combine(nativeDir, "librustdesk.dll");
            if (!File.Exists(expected))
            {
                throw new FileNotFoundException(
                    "real hs-native library not found at the exact expected path", expected);
            }
            _expectedPath = expected;

            // Restrict the loader: System32 + application dir + explicit user dirs.
            // Ambient PATH is excluded. OS system libraries still resolve.
            if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "SetDefaultDllDirectories failed");
            }

            // Owned dependency directories first (DLL directory is already
            // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR for the exact load below).
            if (AddDllDirectory(nativeDir) == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "AddDllDirectory failed for " + nativeDir);
            }
            string depDirs = Environment.GetEnvironmentVariable("HS_NATIVE_DEP_DIRS");
            if (!string.IsNullOrEmpty(depDirs))
            {
                foreach (string d in depDirs.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!Directory.Exists(d))
                    {
                        throw new DirectoryNotFoundException(
                            "HS_NATIVE_DEP_DIRS entry missing (refusing silent skip): " + d);
                    }
                    string full = Path.GetFullPath(d);
                    if (AddDllDirectory(full) == IntPtr.Zero)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(),
                            "AddDllDirectory failed for " + full);
                    }
                }
            }

            NativeLibrary.SetDllImportResolver(typeof(NativeDllGate).Assembly, Resolve);
        }

        private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            if (!string.Equals(libraryName, LibName, StringComparison.OrdinalIgnoreCase))
            {
                // Other imports (e.g. kernel32) use the normal system search.
                return IntPtr.Zero;
            }

            lock (typeof(NativeDllGate))
            {
                if (_loaded)
                {
                    return _handle; // one owned load lifetime; no resolver leak
                }

                if (_expectedPath == null || !File.Exists(_expectedPath))
                {
                    throw new FileNotFoundException("real hs-native library missing", _expectedPath);
                }

                // Exact absolute path + restricted search: DLL's own dir for
                // its dependencies, then default dirs (System32 / app / user).
                IntPtr h = LoadLibraryExW(
                    _expectedPath,
                    IntPtr.Zero,
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                if (h == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "LoadLibraryExW failed for " + _expectedPath);
                }

                string loaded = GetModulePathHard(h);
                if (!string.Equals(loaded, _expectedPath, StringComparison.OrdinalIgnoreCase))
                {
                    FreeLibrary(h);
                    throw new InvalidOperationException(
                        "refusing ambient/fake native DLL: loaded " + loaded +
                        " but expected exact path " + _expectedPath);
                }

                _handle = h;
                _loaded = true;
                return _handle;
            }
        }

        /// <summary>
        /// GetModuleFileNameW with hard failure on error or truncation.
        /// </summary>
        private static string GetModulePathHard(IntPtr module)
        {
            char[] buffer = new char[32768];
            uint n = GetModuleFileNameW(module, buffer, (uint)buffer.Length);
            if (n == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "GetModuleFileNameW failed");
            }
            if (n >= buffer.Length)
            {
                throw new InvalidOperationException(
                    "GetModuleFileNameW truncated (module path exceeds buffer); refusing");
            }
            return new string(buffer, 0, (int)n);
        }

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetDefaultDllDirectories(uint directoryFlags);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr AddDllDirectory(string newDirectory);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleFileNameW(IntPtr hModule, [Out] char[] lpFilename, uint nSize);
    }
}
