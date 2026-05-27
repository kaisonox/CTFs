console.log("[+] Frida patch hook loaded");

// Hook GetUserNameA function
var GetUserNameA = Process.findModuleByName("ADVAPI32.dll").getExportByName("GetUserNameA");
if (GetUserNameA) {
    console.log("[+] Found GetUserNameA at: " + GetUserNameA);
    
    Interceptor.attach(GetUserNameA, {
        onEnter: function(args) {
            this.buffer = args[0];
            this.bufferSize = args[1];
            console.log("[GetUserNameA] Original call - buffer: " + this.buffer + ", size: " + this.bufferSize);
        },
        onLeave: function(retval) {
            console.log("[GetUserNameA] Original return value: " + retval);
            
            try {
                var newUsername = 'TheBoss';
                this.buffer.writeUtf8String(newUsername);
                var newRetval = newUsername.length + 1; // +1 for null terminator
                console.log("[GetUserNameA] Overriding with: " + newUsername + " (length: " + newUsername.length + ")");
                retval.replace(ptr(newRetval));
            } catch (e) {
                console.log("[-] Error overriding GetUserNameA: " + e);
            }
        }
    });
} else {
    console.log("[-] GetUserNameA not found!");
}

// Hook GetSystemTimeAsFileTime function
var GetSystemTimeAsFileTime = Process.findModuleByName("KERNEL32.dll").getExportByName("GetSystemTimeAsFileTime");
if (GetSystemTimeAsFileTime) {
    console.log("[+] Found GetSystemTimeAsFileTime at: " + GetSystemTimeAsFileTime);
    
    Interceptor.attach(GetSystemTimeAsFileTime, {
        onEnter: function(args) {
            this.lpSystemTimeAsFileTime = args[0];
            console.log("[GetSystemTimeAsFileTime] Called - lpSystemTimeAsFileTime: " + this.lpSystemTimeAsFileTime);
        },
        onLeave: function(retval) {
            try {
                // Patch the FILETIME structure with fixed values
                var patchedLowDateTime = 0xDE36AB00;
                var patchedHighDateTime = 0x01DC119B;
                console.log("[GetSystemTimeAsFileTime] Original FILETIME - dwLowDateTime: 0x" + this.lpSystemTimeAsFileTime.readU32().toString(16) + " (" + this.lpSystemTimeAsFileTime.readU32() + "), dwHighDateTime: 0x" + this.lpSystemTimeAsFileTime.add(4).readU32().toString(16) + " (" + this.lpSystemTimeAsFileTime.add(4).readU32() + ")");
                this.lpSystemTimeAsFileTime.writeU32(patchedLowDateTime);
                this.lpSystemTimeAsFileTime.add(4).writeU32(patchedHighDateTime);
                console.log("[GetSystemTimeAsFileTime] PATCHED FILETIME - dwLowDateTime: 0x" + patchedLowDateTime.toString(16) + " (" + patchedLowDateTime + "), dwHighDateTime: 0x" + patchedHighDateTime.toString(16) + " (" + patchedHighDateTime + ")");
            } catch (e) {
                console.log("[-] Error patching time data: " + e);
            }
        }
    });
} else {
    console.log("[-] GetSystemTimeAsFileTime not found!");
}

// Hook GetSystemInfo function
var GetSystemInfo = Process.findModuleByName("KERNEL32.dll").getExportByName("GetSystemInfo");
if (GetSystemInfo) {
    console.log("[+] Found GetSystemInfo at: " + GetSystemInfo);
    
    Interceptor.attach(GetSystemInfo, {
        onEnter: function(args) {
            this.lpSystemInfo = args[0];
            console.log("[GetSystemInfo] Called - lpSystemInfo: " + this.lpSystemInfo);
        },
        onLeave: function(retval) {
            try {
                // SYSTEM_INFO structure offsets:
                // 0-3: dwOemId (4 bytes)
                // 4-7: dwPageSize (4 bytes) 
                // 8-15: lpMinimumApplicationAddress (8 bytes)
                // 16-23: lpMaximumApplicationAddress (8 bytes)
                // 24-31: dwActiveProcessorMask (8 bytes)
                // 32-35: dwNumberOfProcessors (4 bytes)
                var dwNumberOfProcessors = this.lpSystemInfo.add(32).readU32();
                console.log("[GetSystemInfo] Original dwNumberOfProcessors: " + dwNumberOfProcessors);
                // Patch dwNumberOfProcessors to 2
                this.lpSystemInfo.add(32).writeU32(2);
                console.log("[GetSystemInfo] PATCHED dwNumberOfProcessors to 2");
            } catch (e) {
                console.log("[-] Error patching GetSystemInfo: " + e);
            }
        }
    });
} else {
    console.log("[-] GetSystemInfo not found!");
}

// Hook GlobalMemoryStatusEx function
var GlobalMemoryStatusEx = Process.findModuleByName("KERNEL32.dll").getExportByName("GlobalMemoryStatusEx");
if (GlobalMemoryStatusEx) {
    console.log("[+] Found GlobalMemoryStatusEx at: " + GlobalMemoryStatusEx);
    
    Interceptor.attach(GlobalMemoryStatusEx, {
        onEnter: function(args) {
            this.lpBuffer = args[0];
            console.log("[GlobalMemoryStatusEx] Called - lpBuffer: " + this.lpBuffer);
        },
        onLeave: function(retval) {
            try {
                // Patch ullTotalPhys to 6143 MB (6143 * 1024 * 1024 bytes)
                var patchedMemory = 6143 * 1024 * 1024; // 6143 MB in bytes
                this.lpBuffer.add(8).writeU64(patchedMemory); // ullTotalPhys is at offset 8
                console.log("[GlobalMemoryStatusEx] PATCHED ullTotalPhys to " + patchedMemory + " bytes (6143 MB)");
            } catch (e) {
                console.log("[-] Error patching GlobalMemoryStatusEx: " + e);
            }
        }
    });
} else {
    console.log("[-] GlobalMemoryStatusEx not found!");
}

// Hook GetComputerNameA function
var GetComputerNameA = Process.findModuleByName("KERNEL32.dll").getExportByName("GetComputerNameA");
if (GetComputerNameA) {
    console.log("[+] Found GetComputerNameA at: " + GetComputerNameA);
    
    Interceptor.attach(GetComputerNameA, {
        onEnter: function(args) {
            this.buffer = args[0];
            this.bufferSize = args[1];
            console.log("[GetComputerNameA] Original call - buffer: " + this.buffer + ", size: " + this.bufferSize);
        },
        onLeave: function(retval) {
            console.log("[GetComputerNameA] Original return value: " + retval);
            
            try {
                var newHostname = 'THUNDERNODE';
                this.buffer.writeUtf8String(newHostname);
                var newRetval = newHostname.length + 1; // +1 for null terminator
                console.log("[GetComputerNameA] Overriding with: " + newHostname + " (length: " + newHostname.length + ")");
                retval.replace(ptr(newRetval));
            } catch (e) {
                console.log("[-] Error overriding GetComputerNameA: " + e);
            }
        }
    });
} else {
    console.log("[-] GetComputerNameA not found!");
}

// Hook memcpy
var memcpy = Process.findModuleByName("VCRUNTIME140.dll").getExportByName("memcpy");
if (memcpy) {
    console.log("[+] Found memcpy at: " + memcpy);

    Interceptor.attach(memcpy, {
        onEnter: function(args) {
            this.dest = args[0];
            this.src = args[1];
            this.size = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (this.size <= 0) return;
            var srcString = null;
            try {
                srcString = this.src.readUtf8String(this.size);
                if (srcString && srcString.length > 2) {
                    console.log("[memcpy] ASCII: " + srcString);
                }
            } catch (e) {
                console.log("[-] Cannot decode memcpy src: " + e);
            }
        }
    });
} else {
    console.log("[-] memcpy not found!");
}

console.log("[+] Patch hook ready");
