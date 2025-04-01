/*
Monitor files managed by the application.

Purpose:
- Monitors and logs files being used by the application.
- Captures the content written into files through FileOutputStream.

Functionality:
- Intercepts constructors of FileOutputStream and FileInputStream to track the file being opened for reading and writing.
- Captures data written via the `write()` method, storing it in a temporary buffer.
- Dumps logged information (file path and data contents) to the console upon file closure.

Example Usage:
frida -U -N <package_name> -l .\file_monitor.js
*/

console.log("*******************************************************");
console.log("* Frida Hooking Script for File I/O Operations");
console.log("* Created by Francesco Varotto - GitHub: https://github.com/francevarotz98/");
console.log("*******************************************************");

Java.perform(function() {
    var openedfile = "";
    var data = {
        "file": "",
        "content": []
    };
    var isOpen = false;
    var index = 0;

    // Hook FileOutputStream (existing hooks)
    var fos = Java.use('java.io.FileOutputStream');
    var fos_construct_2 = fos.$init.overload('java.lang.String');
    var fos_construct_3 = fos.$init.overload('java.io.File');
    var fos_construct_4 = fos.$init.overload('java.lang.String', 'boolean');
    var fos_construct_5 = fos.$init.overload('java.io.File', 'boolean');
    var fos_write_1 = fos.write.overload('[B', 'int', 'int');
    var fos_close = fos.close;

    // Hook FileInputStream (new hooks)
    var fis = Java.use('java.io.FileInputStream');
    var fis_contruct_1 = fis.$init.overload('java.io.File');
    var fis_contruct_2 = fis.$init.overload('java.io.FileDescriptor');
    var fis_contruct_3 = fis.$init.overload('java.lang.String');

    // Dump function used by both streams
    function dump(data) {
        // Bypass logging a specific file if needed
        if(openedfile !== "/path/to/file/file.extension") {
            console.log("[*] file: " + openedfile);
            /*
            // Uncomment the following if you want to log the file content as well:
            // Convert byte array to a readable string
            var buffer = Java.array('byte', data["content"]);
            var StringClass = Java.use('java.lang.String');
            var fileContent = StringClass.$new(buffer, "UTF-8");
            console.log("[*] file content:\n" + fileContent);
            */
            console.log("----------");
        }
        
        // Reset data for the next file hook
        var tmp_name = openedfile.split("/");
        tmp_name = tmp_name[tmp_name.length - 1];
        data["file"] = tmp_name;
        data["content"] = [];
        index = 0;
    }

    ///////////////// FileOutputStream Hooks ///////////////////
    fos_construct_2.implementation = function(file) {
        var filename = file;
        if (openedfile != filename) {
            openedfile = filename;
            isOpen = true;
        }
        return fos_construct_2.call(this, file);
    };

    fos_construct_3.implementation = function(file) {
        var filename = file.getAbsolutePath();
        if (openedfile != filename) {
            openedfile = filename;
            isOpen = true;
        }
        return fos_construct_3.call(this, file);
    };

    fos_construct_4.implementation = function(file, flag) {
        var filename = file;
        if (openedfile != filename) {
            openedfile = filename;
            isOpen = true;
        }
        return fos_construct_4.call(this, file, flag);
    };

    fos_construct_5.implementation = function(file, flag) {
        var filename = file.getAbsolutePath();
        if (openedfile != filename) {
            openedfile = filename;
            isOpen = true;
        }
        return fos_construct_5.call(this, file, flag);
    };

    fos_write_1.implementation = function(arr, offset, length) {
        for (var i = offset; i < offset + length; i++) {
            data["content"][index] = arr[i];
            index++;
        }
        return fos_write_1.call(this, arr, offset, length);
    };

    fos_close.implementation = function() {
        dump(data);
        return fos_close.call(this);
    };

    ///////////////// FileInputStream Hooks ///////////////////
    // Hook constructors to capture the file being read
    fis_contruct_1.implementation = function(file) {
        var filename = file.getAbsolutePath();
        if (openedfile != filename) {
            openedfile = filename;
            isOpen = true;
        }
        return fis_contruct_1.call(this, file);
    };

    fis_contruct_2.implementation = function(fd) {
        // When a FileDescriptor is used, we may not have a path.
        if (openedfile != "FileDescriptor") {
            openedfile = "FileDescriptor";
            isOpen = true;
        }
        return fis_contruct_2.call(this, fd);
    };

    fis_contruct_3.implementation = function(filename) {
        if (openedfile != filename) {
            openedfile = filename;
            isOpen = true;
        }
        return fis_contruct_3.call(this, filename);
    };

    // Hook the various read methods to capture the data being read
    var fis_read_0 = fis.read.overload(); // read()
    var fis_read_1 = fis.read.overload('[B'); // read(byte[])
    var fis_read_2 = fis.read.overload('[B', 'int', 'int'); // read(byte[], int, int)
    var fis_close = fis.close;

    fis_read_0.implementation = function() {
        var ret = fis_read_0.call(this);
        if(ret !== -1) {
            data["content"].push(ret);
        }
        return ret;
    };

    fis_read_1.implementation = function(b) {
        var ret = fis_read_1.call(this, b);
        if(ret > 0) {
            for (var i = 0; i < ret; i++) {
                data["content"].push(b[i]);
            }
        }
        return ret;
    };

    fis_read_2.implementation = function(b, off, len) {
        var ret = fis_read_2.call(this, b, off, len);
        if(ret > 0) {
            for (var i = off; i < off + ret; i++) {
                data["content"].push(b[i]);
            }
        }
        return ret;
    };

    fis_close.implementation = function() {
        dump(data);
        return fis_close.call(this);
    };

});
