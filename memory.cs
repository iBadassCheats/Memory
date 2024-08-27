using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

public partial class memory
{
    public static memory mem = new memory();
    
    public enum InitializeResult
    {
        Memeory_Successfully,
        Memeory_Failed
    }

    public InitializeResult Initialize(string process)
    {
        try
        {
            Process = Process.GetProcessesByName(process)[0];

            Handle = OpenProcess(0x1F0FFF, true, Process.Id);

            Is64Bit = Environment.Is64BitOperatingSystem && (IsWow64Process(Handle, out bool retVal) && !retVal);

            MainModule = Process.MainModule;

            return InitializeResult.Memeory_Successfully;
        }
        catch
        {
            return InitializeResult.Memeory_Failed;
        }
    }

    public static string SyncAOBSCAN(long start = 0, long end = long.MaxValue, string search = "", long offset = 0)
    {
        return AOBSCAN(start, end, search, offset).GetAwaiter().GetResult();
    }

    private static async Task<string> AOBSCAN(long start, long end, string search, long offset)
    {
        string result = string.Empty;

        try
        {
            IEnumerable<long> addresses = await mem.AoBScan(start, end, search, true, true, true, false);
            long address = addresses.FirstOrDefault();

            checked
            {
                if (address != 0)
                {
                    address += offset;
                }
            }

            result = $"{address:X}";
        }
        catch (InvalidOperationException ex)
        {

        }

        return result;
    }

    #region Process

    public Process Process { get; set; }
    public IntPtr Handle { get; set; }
    public bool Is64Bit { get; set; }
    public ProcessModule MainModule { get; set; }

    #endregion

    #region MemoryRegionResult

    struct MemoryRegionResult
    {
        public UIntPtr CurrentBaseAddress { get; set; }
        public long RegionSize { get; set; }
        public UIntPtr RegionBase { get; set; }

    }

    #endregion

    #region Imports

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(
    UInt32 dwDesiredAccess,
    bool bInheritHandle,
    Int32 dwProcessId
    );

#if WINXP
#else
    [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
    public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION32 lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
    public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION64 lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
#endif

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] IntPtr lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);

    // Added to avoid casting to UIntPtr
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32")]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

    // privileges
    public const int PROCESS_CREATE_THREAD = 0x0002;
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const int PROCESS_VM_READ = 0x0010;

    // used for memory allocation
    public const uint MEM_FREE = 0x10000;
    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;

    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;

    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOACCESS = 0x01;

    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_IMAGE = 0x1000000;
    public const uint MEM_MAPPED = 0x40000;

    public struct SYSTEM_INFO
    {
        public ushort processorArchitecture;
        ushort reserved;
        public uint pageSize;
        public UIntPtr minimumApplicationAddress;
        public UIntPtr maximumApplicationAddress;
        public IntPtr activeProcessorMask;
        public uint numberOfProcessors;
        public uint processorType;
        public uint allocationGranularity;
        public ushort processorLevel;
        public ushort processorRevision;
    }

    public struct MEMORY_BASIC_INFORMATION32
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public uint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public struct MEMORY_BASIC_INFORMATION64
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public uint __alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint __alignment2;
    }

    public struct MEMORY_BASIC_INFORMATION
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public long RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        GuardModifierflag = 0x100,
        NoCacheModifierflag = 0x200,
        WriteCombineModifierflag = 0x400
    }

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtQueryInformationThread(
    IntPtr threadHandle,
    ThreadInfoClass threadInformationClass,
    IntPtr threadInformation,
    int threadInformationLength,
    IntPtr returnLengthPtr);
    public enum ThreadInfoClass : int
    {
        ThreadQuerySetWin32StartAddress = 9
    }

    #endregion

    #region Writing

    ConcurrentDictionary<string, CancellationTokenSource> FreezeTokenSrcs = new ConcurrentDictionary<string, CancellationTokenSource>();

    public bool FreezeValue(string address, string type, string value)
    {
        CancellationTokenSource cts = new CancellationTokenSource();

        if (FreezeTokenSrcs.ContainsKey(address))
        {
            Debug.WriteLine("Changing Freezing Address " + address + " Value " + value);
            try
            {
                FreezeTokenSrcs[address].Cancel();
                FreezeTokenSrcs.TryRemove(address, out _);
            }
            catch
            {
                Debug.WriteLine("ERROR: Avoided a crash. Address " + address + " was not frozen.");
                return false;
            }
        }
        else
        {
            Debug.WriteLine("Adding Freezing Address " + address + " Value " + value);
        }

        FreezeTokenSrcs.TryAdd(address, cts);

        Task.Factory.StartNew(() =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                WriteMemory(address, type, value);
                Thread.Sleep(25);
            }
        },
        cts.Token);

        return true;
    }

    public void UnfreezeValue(string address)
    {
        Debug.WriteLine("Un-Freezing Address " + address);
        try
        {
            lock (FreezeTokenSrcs)
            {
                FreezeTokenSrcs[address].Cancel();
                FreezeTokenSrcs.TryRemove(address, out _);
            }
        }
        catch
        {
            Debug.WriteLine("ERROR: Address " + address + " was not frozen.");
        }
    }

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr hProcess, UIntPtr lpAddress,
    IntPtr dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);

    public bool ChangeProtection(string code, MemoryProtection newProtection, out MemoryProtection oldProtection)
    {
        UIntPtr theCode = GetCode(code);
        if (theCode == UIntPtr.Zero
            || Handle == IntPtr.Zero)
        {
            oldProtection = default;
            return false;
        }

        return VirtualProtectEx(Handle, theCode, (IntPtr)(Is64Bit ? 8 : 4), newProtection, out oldProtection);
    }

    public bool WriteMemory(string code, string type, string write, System.Text.Encoding stringEncoding = null, bool RemoveWriteProtection = true)
    {
        byte[] memory = new byte[4];
        int size = 4;

        UIntPtr theCode;
        theCode = GetCode(code);

        if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
            return false;

        if (type.ToLower() == "float")
        {
            write = Convert.ToString(float.Parse(write, CultureInfo.InvariantCulture));
            memory = BitConverter.GetBytes(Convert.ToSingle(write));
            size = 4;
        }
        else if (type.ToLower() == "int")
        {
            memory = BitConverter.GetBytes(Convert.ToInt32(write));
            size = 4;
        }
        else if (type.ToLower() == "byte")
        {
            memory = new byte[1];
            memory[0] = Convert.ToByte(write, 16);
            size = 1;
        }
        else if (type.ToLower() == "2bytes")
        {
            memory = new byte[2];
            memory[0] = (byte)(Convert.ToInt32(write) % 256);
            memory[1] = (byte)(Convert.ToInt32(write) / 256);
            size = 2;
        }
        else if (type.ToLower() == "bytes")
        {
            if (write.Contains(",") || write.Contains(" "))
            {
                string[] stringBytes;
                if (write.Contains(","))
                    stringBytes = write.Split(',');
                else
                    stringBytes = write.Split(' ');

                int c = stringBytes.Count();
                memory = new byte[c];
                for (int i = 0; i < c; i++)
                {
                    memory[i] = Convert.ToByte(stringBytes[i], 16);
                }
                size = stringBytes.Count();
            }
            else
            {
                memory = new byte[1];
                memory[0] = Convert.ToByte(write, 16);
                size = 1;
            }
        }
        else if (type.ToLower() == "double")
        {
            memory = BitConverter.GetBytes(Convert.ToDouble(write));
            size = 8;
        }
        else if (type.ToLower() == "long")
        {
            memory = BitConverter.GetBytes(Convert.ToInt64(write));
            size = 8;
        }
        else if (type.ToLower() == "string")
        {
            if (stringEncoding == null)
                memory = System.Text.Encoding.UTF8.GetBytes(write);
            else
                memory = stringEncoding.GetBytes(write);
            size = memory.Length;
        }

        MemoryProtection OldMemProt = 0x00;
        bool WriteProcMem = false;
        if (RemoveWriteProtection)
            ChangeProtection(code, MemoryProtection.ExecuteReadWrite, out OldMemProt); // change protection
        WriteProcMem = WriteProcessMemory(Handle, theCode, memory, (UIntPtr)size, IntPtr.Zero);
        if (RemoveWriteProtection)
            ChangeProtection(code, OldMemProt, out _); // restore
        return WriteProcMem;
    }

    public void WriteBytes(UIntPtr address, byte[] write)
    {
        WriteProcessMemory(Handle, address, write, (UIntPtr)write.Length, out IntPtr bytesRead);
    }

    #endregion

    #region Reading

    public byte[] ReadBytes(string code, long length)
    {
        byte[] memory = new byte[length];
        UIntPtr theCode = GetCode(code);
        if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
            return null;

        if (!ReadProcessMemory(Handle, theCode, memory, (UIntPtr)length, IntPtr.Zero))
            return null;

        return memory;
    }

    public float ReadFloat(string code, bool round = true)
    {
        byte[] memory = new byte[4];

        UIntPtr theCode = GetCode(code);
        if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
            return 0;

        try
        {
            if (!ReadProcessMemory(Handle, theCode, memory, (UIntPtr)4, IntPtr.Zero)) return 0;
            var address = BitConverter.ToSingle(memory, 0);
            var returnValue = address;
            if (round) returnValue = (float)Math.Round(address, 2);
            return returnValue;
        }
        catch
        {
            return 0;
        }
    }

    public string ReadString(string code, int length = 32, bool zeroTerminated = true, System.Text.Encoding stringEncoding = null)
    {
        if (stringEncoding == null)
            stringEncoding = System.Text.Encoding.UTF8;

        byte[] memoryNormal = new byte[length];
        UIntPtr theCode = GetCode(code);
        if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
            return "";

        if (ReadProcessMemory(Handle, theCode, memoryNormal, (UIntPtr)length, IntPtr.Zero))
            return (zeroTerminated) ? stringEncoding.GetString(memoryNormal).Split('\0')[0] : stringEncoding.GetString(memoryNormal);
        else
            return "";
    }

    public double ReadDouble(string code, bool round = true)
    {
        byte[] memory = new byte[8];

        UIntPtr theCode = GetCode(code);
        if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
            return 0;

        try
        {
            if (ReadProcessMemory(Handle, theCode, memory, (UIntPtr)8, IntPtr.Zero))
            {
                double address = BitConverter.ToDouble(memory, 0);
                double returnValue = (double)address;
                if (round)
                    returnValue = (double)Math.Round(address, 2);
                return returnValue;
            }
            else
                return 0;
        }
        catch
        {
            return 0;
        }
    }

    public int ReadInt(string code)
    {
        byte[] memory = new byte[4];
        UIntPtr theCode = GetCode(code);
        if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
            return 0;

        if (ReadProcessMemory(Handle, theCode, memory, (UIntPtr)4, IntPtr.Zero))
            return BitConverter.ToInt32(memory, 0);
        else
            return 0;
    }

    public long ReadLong(string code)
    {
        byte[] memory = new byte[16];
        UIntPtr theCode = GetCode(code);

        if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
            return 0;

        if (ReadProcessMemory(Handle, theCode, memory, (UIntPtr)8, IntPtr.Zero))
            return BitConverter.ToInt64(memory, 0);
        else
            return 0;
    }

    public int ReadByte(string code)
    {
        byte[] memoryTiny = new byte[1];

        UIntPtr theCode = GetCode(code);
        if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
            return 0;

        if (ReadProcessMemory(Handle, theCode, memoryTiny, (UIntPtr)1, IntPtr.Zero))
            return memoryTiny[0];

        return 0;
    }

    #endregion

    #region AOBScan

    public Task<IEnumerable<long>> AoBScan(long start, long end, string search, bool readable, bool writable, bool executable, bool mapped)
    {
        return Task.Run(() =>
        {
            var memRegionList = new List<MemoryRegionResult>();

            string memCode = LoadCode(search);

            string[] stringByteArray = memCode.Split(' ');

            byte[] aobPattern = new byte[stringByteArray.Length];
            byte[] mask = new byte[stringByteArray.Length];

            for (var i = 0; i < stringByteArray.Length; i++)
            {
                string ba = stringByteArray[i];

                if (ba == "??" || (ba.Length == 1 && ba == "?"))
                {
                    mask[i] = 0x00;
                    stringByteArray[i] = "0x00";
                }
                else if (Char.IsLetterOrDigit(ba[0]) && ba[1] == '?')
                {
                    mask[i] = 0xF0;
                    stringByteArray[i] = ba[0] + "0";
                }
                else if (Char.IsLetterOrDigit(ba[1]) && ba[0] == '?')
                {
                    mask[i] = 0x0F;
                    stringByteArray[i] = "0" + ba[1];
                }
                else
                    mask[i] = 0xFF;
            }


            for (int i = 0; i < stringByteArray.Length; i++)
                aobPattern[i] = (byte)(Convert.ToByte(stringByteArray[i], 16) & mask[i]);

            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            UIntPtr proc_min_address = sys_info.minimumApplicationAddress;
            UIntPtr proc_max_address = sys_info.maximumApplicationAddress;

            if (start < (long)proc_min_address.ToUInt64())
                start = (long)proc_min_address.ToUInt64();

            if (end > (long)proc_max_address.ToUInt64())
                end = (long)proc_max_address.ToUInt64();

            Debug.WriteLine("[DEBUG] memory scan starting... (start:0x" + start.ToString(MSize()) + " end:0x" + end.ToString(MSize()) + " time:" + DateTime.Now.ToString("h:mm:ss tt") + ")");
            UIntPtr currentBaseAddress = new UIntPtr((ulong)start);

            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();

            while (VirtualQueryEx(Handle, currentBaseAddress, out memInfo).ToUInt64() != 0 &&
                       currentBaseAddress.ToUInt64() < (ulong)end &&
                       currentBaseAddress.ToUInt64() + (ulong)memInfo.RegionSize >
                       currentBaseAddress.ToUInt64())
            {
                bool isValid = memInfo.State == MEM_COMMIT;
                isValid &= memInfo.BaseAddress.ToUInt64() < (ulong)proc_max_address.ToUInt64();
                isValid &= ((memInfo.Protect & PAGE_GUARD) == 0);
                isValid &= ((memInfo.Protect & PAGE_NOACCESS) == 0);
                isValid &= (memInfo.Type == MEM_PRIVATE) || (memInfo.Type == MEM_IMAGE);
                if (mapped)
                    isValid &= (memInfo.Type == MEM_MAPPED);

                if (isValid)
                {
                    bool isReadable = (memInfo.Protect & PAGE_READONLY) > 0;

                    bool isWritable = ((memInfo.Protect & PAGE_READWRITE) > 0) ||
                                      ((memInfo.Protect & PAGE_WRITECOPY) > 0) ||
                                      ((memInfo.Protect & PAGE_EXECUTE_READWRITE) > 0) ||
                                      ((memInfo.Protect & PAGE_EXECUTE_WRITECOPY) > 0);

                    bool isExecutable = ((memInfo.Protect & PAGE_EXECUTE) > 0) ||
                                        ((memInfo.Protect & PAGE_EXECUTE_READ) > 0) ||
                                        ((memInfo.Protect & PAGE_EXECUTE_READWRITE) > 0) ||
                                        ((memInfo.Protect & PAGE_EXECUTE_WRITECOPY) > 0);

                    isReadable &= readable;
                    isWritable &= writable;
                    isExecutable &= executable;

                    isValid &= isReadable || isWritable || isExecutable;
                }

                if (!isValid)
                {
                    currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + (ulong)memInfo.RegionSize);
                    continue;
                }

                MemoryRegionResult memRegion = new MemoryRegionResult
                {
                    CurrentBaseAddress = currentBaseAddress,
                    RegionSize = memInfo.RegionSize,
                    RegionBase = memInfo.BaseAddress
                };

                currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + (ulong)memInfo.RegionSize);

                if (memRegionList.Count > 0)
                {
                    var previousRegion = memRegionList[memRegionList.Count - 1];

                    if ((long)previousRegion.RegionBase + previousRegion.RegionSize == (long)memInfo.BaseAddress)
                    {
                        memRegionList[memRegionList.Count - 1] = new MemoryRegionResult
                        {
                            CurrentBaseAddress = previousRegion.CurrentBaseAddress,
                            RegionBase = previousRegion.RegionBase,
                            RegionSize = previousRegion.RegionSize + memInfo.RegionSize
                        };

                        continue;
                    }
                }

                memRegionList.Add(memRegion);
            }

            ConcurrentBag<long> bagResult = new ConcurrentBag<long>();

            Parallel.ForEach(memRegionList,
                             (item, parallelLoopState, index) =>
                             {
                                 long[] compareResults = CompareScan(item, aobPattern, mask);

                                 foreach (long result in compareResults)
                                     bagResult.Add(result);
                             });

            Debug.WriteLine("[DEBUG] memory scan completed. (time:" + DateTime.Now.ToString("h:mm:ss tt") + ")");

            return bagResult.ToList().OrderBy(c => c).AsEnumerable();
        });
    }

    private long[] CompareScan(MemoryRegionResult item, byte[] aobPattern, byte[] mask)
    {
        if (mask.Length != aobPattern.Length)
            throw new ArgumentException($"{nameof(aobPattern)}.Length != {nameof(mask)}.Length");

        IntPtr buffer = Marshal.AllocHGlobal((int)item.RegionSize);

        ReadProcessMemory(Handle, item.CurrentBaseAddress, buffer, (UIntPtr)item.RegionSize, out ulong bytesRead);

        int result = 0 - aobPattern.Length;
        List<long> ret = new List<long>();
        unsafe
        {
            do
            {

                result = FindPattern((byte*)buffer.ToPointer(), (int)bytesRead, aobPattern, mask, result + aobPattern.Length);

                if (result >= 0)
                    ret.Add((long)item.CurrentBaseAddress + result);

            } while (result != -1);
        }

        Marshal.FreeHGlobal(buffer);

        return ret.ToArray();
    }


    private unsafe int FindPattern(byte* body, int bodyLength, byte[] pattern, byte[] masks, int start = 0)
    {
        int foundIndex = -1;

        if (bodyLength <= 0 || pattern.Length <= 0 || start > bodyLength - pattern.Length ||
            pattern.Length > bodyLength) return foundIndex;

        for (int index = start; index <= bodyLength - pattern.Length; index++)
        {
            if (((body[index] & masks[0]) == (pattern[0] & masks[0])))
            {
                var match = true;
                for (int index2 = pattern.Length - 1; index2 >= 1; index2--)
                {
                    if ((body[index + index2] & masks[index2]) == (pattern[index2] & masks[index2])) continue;
                    match = false;
                    break;

                }

                if (!match) continue;

                foundIndex = index;
                break;
            }
        }

        return foundIndex;
    }

    #endregion

    public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer)
    {
        UIntPtr retVal;

        // TODO: Need to change this to only check once.
        if (Is64Bit || IntPtr.Size == 8)
        {
            // 64 bit
            MEMORY_BASIC_INFORMATION64 tmp64 = new MEMORY_BASIC_INFORMATION64();
            retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp64, new UIntPtr((uint)Marshal.SizeOf(tmp64)));

            lpBuffer.BaseAddress = tmp64.BaseAddress;
            lpBuffer.AllocationBase = tmp64.AllocationBase;
            lpBuffer.AllocationProtect = tmp64.AllocationProtect;
            lpBuffer.RegionSize = (long)tmp64.RegionSize;
            lpBuffer.State = tmp64.State;
            lpBuffer.Protect = tmp64.Protect;
            lpBuffer.Type = tmp64.Type;

            return retVal;
        }
        MEMORY_BASIC_INFORMATION32 tmp32 = new MEMORY_BASIC_INFORMATION32();

        retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp32, new UIntPtr((uint)Marshal.SizeOf(tmp32)));

        lpBuffer.BaseAddress = tmp32.BaseAddress;
        lpBuffer.AllocationBase = tmp32.AllocationBase;
        lpBuffer.AllocationProtect = tmp32.AllocationProtect;
        lpBuffer.RegionSize = tmp32.RegionSize;
        lpBuffer.State = tmp32.State;
        lpBuffer.Protect = tmp32.Protect;
        lpBuffer.Type = tmp32.Type;

        return retVal;
    }

    public string LoadCode(string name)
    {
        StringBuilder returnCode = new StringBuilder(1024);

        return returnCode.Append(name).ToString();
    }

    public UIntPtr GetCode(string name, int size = 8)
    {
        string theCode = "";

        if (Is64Bit)
        {
            if (size == 8) size = 16;
            return Get64BitCode(name, size);
        }

        theCode = name;

        if (String.IsNullOrEmpty(theCode))
        {
            return UIntPtr.Zero;
        }
        else
        {

        }

        if (theCode.Contains(" "))
            theCode = theCode.Replace(" ", String.Empty);

        if (!theCode.Contains("+") && !theCode.Contains(","))
        {
            try
            {
                return new UIntPtr(Convert.ToUInt32(theCode, 16));
            }
            catch
            {
                Console.WriteLine("Error in GetCode(). Failed to read address " + theCode);
                return UIntPtr.Zero;
            }
        }

        string newOffsets = theCode;

        if (theCode.Contains("+"))
            newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);

        byte[] memoryAddress = new byte[size];

        if (newOffsets.Contains(','))
        {
            List<int> offsetsList = new List<int>();

            string[] newerOffsets = newOffsets.Split(',');
            foreach (string oldOffsets in newerOffsets)
            {
                string test = oldOffsets;
                if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x", "");
                int preParse = 0;
                if (!oldOffsets.Contains("-"))
                    preParse = Int32.Parse(test, NumberStyles.AllowHexSpecifier);
                else
                {
                    test = test.Replace("-", "");
                    preParse = Int32.Parse(test, NumberStyles.AllowHexSpecifier);
                    preParse = preParse * -1;
                }
                offsetsList.Add(preParse);
            }
            int[] offsets = offsetsList.ToArray();

            if (theCode.Contains("base") || theCode.Contains("main"))
                ReadProcessMemory(Handle, (UIntPtr)((int)MainModule.BaseAddress + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
            else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
            {
                string[] moduleName = theCode.Split('+');
                IntPtr altModule = IntPtr.Zero;
                if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                {
                    string theAddr = moduleName[0];
                    if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                    altModule = (IntPtr)Int32.Parse(theAddr, NumberStyles.HexNumber);
                }
                else
                {
                    try
                    {
                        altModule = GetModuleAddressByName(moduleName[0]);
                    }
                    catch
                    {
                        Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                        //Debug.WriteLine("Modules: " + string.Join(",", Modules));
                    }
                }
                ReadProcessMemory(Handle, (UIntPtr)((int)altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
            }
            else
                ReadProcessMemory(Handle, (UIntPtr)(offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);

            uint num1 = BitConverter.ToUInt32(memoryAddress, 0); //ToUInt64 causes arithmetic overflow.

            UIntPtr base1 = (UIntPtr)0;

            for (int i = 1; i < offsets.Length; i++)
            {
                base1 = new UIntPtr(Convert.ToUInt32(num1 + offsets[i]));
                ReadProcessMemory(Handle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                num1 = BitConverter.ToUInt32(memoryAddress, 0); //ToUInt64 causes arithmetic overflow.
            }
            return base1;
        }
        else // no offsets
        {
            int trueCode = Convert.ToInt32(newOffsets, 16);
            IntPtr altModule = IntPtr.Zero;
            //Debug.WriteLine("newOffsets=" + newOffsets);
            if (theCode.ToLower().Contains("base") || theCode.ToLower().Contains("main"))
                altModule = MainModule.BaseAddress;
            else if (!theCode.ToLower().Contains("base") && !theCode.ToLower().Contains("main") && theCode.Contains("+"))
            {
                string[] moduleName = theCode.Split('+');
                if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                {
                    string theAddr = moduleName[0];
                    if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                    altModule = (IntPtr)Int32.Parse(theAddr, NumberStyles.HexNumber);
                }
                else
                {
                    try
                    {
                        altModule = GetModuleAddressByName(moduleName[0]);
                    }
                    catch
                    {
                        Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                        //Debug.WriteLine("Modules: " + string.Join(",", Modules));
                    }
                }
            }
            else
                altModule = GetModuleAddressByName(theCode.Split('+')[0]);
            return (UIntPtr)((int)altModule + trueCode);
        }
    }

    public IntPtr GetModuleAddressByName(string name)
    {
        return Process.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, name, StringComparison.OrdinalIgnoreCase)).BaseAddress;
    }

    public UIntPtr Get64BitCode(string name, int size = 16)
    {
        string theCode = "";
        theCode = name;

        if (String.IsNullOrEmpty(theCode))
            return UIntPtr.Zero;

        // remove spaces
        if (theCode.Contains(" "))
            theCode.Replace(" ", String.Empty);

        string newOffsets = theCode;
        if (theCode.Contains("+"))
            newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);

        byte[] memoryAddress = new byte[size];

        if (!theCode.Contains("+") && !theCode.Contains(","))
        {
            try
            {
                return new UIntPtr(Convert.ToUInt64(theCode, 16));
            }
            catch
            {
                Console.WriteLine("Error in GetCode(). Failed to read address " + theCode);
                return UIntPtr.Zero;
            }
        }

        if (newOffsets.Contains(','))
        {
            List<Int64> offsetsList = new List<Int64>();

            string[] newerOffsets = newOffsets.Split(',');
            foreach (string oldOffsets in newerOffsets)
            {
                string test = oldOffsets;
                if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x", "");
                Int64 preParse = 0;
                if (!oldOffsets.Contains("-"))
                    preParse = Int64.Parse(test, NumberStyles.AllowHexSpecifier);
                else
                {
                    test = test.Replace("-", "");
                    preParse = Int64.Parse(test, NumberStyles.AllowHexSpecifier);
                    preParse = preParse * -1;
                }
                offsetsList.Add(preParse);
            }
            Int64[] offsets = offsetsList.ToArray();

            if (theCode.Contains("base") || theCode.Contains("main"))
                ReadProcessMemory(Handle, (UIntPtr)((Int64)MainModule.BaseAddress + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
            else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
            {
                string[] moduleName = theCode.Split('+');
                IntPtr altModule = IntPtr.Zero;
                if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                    altModule = (IntPtr)Int64.Parse(moduleName[0], System.Globalization.NumberStyles.HexNumber);
                else
                {
                    try
                    {
                        altModule = GetModuleAddressByName(moduleName[0]);
                    }
                    catch
                    {
                        Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                        //Debug.WriteLine("Modules: " + string.Join(",", Modules));
                    }
                }
                ReadProcessMemory(Handle, (UIntPtr)((Int64)altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
            }
            else // no offsets
                ReadProcessMemory(Handle, (UIntPtr)(offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);

            Int64 num1 = BitConverter.ToInt64(memoryAddress, 0);

            UIntPtr base1 = (UIntPtr)0;

            for (int i = 1; i < offsets.Length; i++)
            {
                base1 = new UIntPtr(Convert.ToUInt64(num1 + offsets[i]));
                ReadProcessMemory(Handle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                num1 = BitConverter.ToInt64(memoryAddress, 0);
            }
            return base1;
        }
        else
        {
            Int64 trueCode = Convert.ToInt64(newOffsets, 16);
            IntPtr altModule = IntPtr.Zero;
            if (theCode.Contains("base") || theCode.Contains("main"))
                altModule = MainModule.BaseAddress;
            else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
            {
                string[] moduleName = theCode.Split('+');
                if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                {
                    string theAddr = moduleName[0];
                    if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                    altModule = (IntPtr)Int64.Parse(theAddr, NumberStyles.HexNumber);
                }
                else
                {
                    try
                    {
                        altModule = GetModuleAddressByName(moduleName[0]);
                    }
                    catch
                    {
                        Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                        //Debug.WriteLine("Modules: " + string.Join(",", Modules));
                    }
                }
            }
            else
                altModule = GetModuleAddressByName(theCode.Split('+')[0]);
            return (UIntPtr)((Int64)altModule + trueCode);
        }
    }

    public string MSize()
    {
        if (Is64Bit)
            return ("x16");
        else
            return ("x8");
    }
}
