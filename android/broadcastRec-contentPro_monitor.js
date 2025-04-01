/*
TODO: hook all the overloads

Monitor broadcast receivers and content providers used by the app.

Example Usage:
frida -U -N <package_name> -l .\file_monitor.js
*/

console.log("*******************************************************");
console.log("* Frida Hooking Script for File I/O Operations");
console.log("* Created by Francesco Varotto - GitHub: https://github.com/francevarotz98/");
console.log("*******************************************************");


Java.perform(function() {
    // Hook conent providers
    
    // Get ContentResolver class
    var ContentResolver = Java.use('android.content.ContentResolver');

    // Hook query methods and its overloads
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
        console.log("Querying ContentProvider: " + uri.toString());
        console.log("Projection: " + projection);
        console.log("Selection: " + selection);
        console.log("Selection Args: " + selectionArgs);
        console.log("Sort Order: " + sortOrder);

        // Call original query method
        return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };

    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function(uri, projection, queryArgs, cancellationSignal) {
        console.log("Querying ContentProvider: " + uri.toString());
        console.log("Projection: " + projection);
        console.log("Query Args: " + queryArgs);
        console.log("CancellationSignal: " + cancellationSignal);

        // Call original query method
        return this.query(uri, projection, queryArgs, cancellationSignal);
    };

    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(uri, projection, selection, selectionArgs, sortOrder, cancellationSignal) {
        console.log("Querying ContentProvider (with CancellationSignal): " + uri.toString());
        console.log("Projection: " + projection);
        console.log("Selection: " + selection);
        console.log("Selection Args: " + selectionArgs);
        console.log("Sort Order: " + sortOrder);
        console.log("CancellationSignal: " + cancellationSignal);

        // Call the original query method
        return this.query(uri, projection, selection, selectionArgs, sortOrder, cancellationSignal);
    };

    // Hook insert method
    ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues').implementation = function(uri, values) {
        console.log("Inserting into ContentProvider: " + uri.toString());
        console.log("ContentValues: " + values);
        
        // Call the original insert method
        return this.insert(uri, values);
    };

    // Hook update method
    ContentResolver.update.overload('android.net.Uri', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function(uri, values, selection, selectionArgs) {
        console.log("Updating ContentProvider: " + uri.toString());
        console.log("ContentValues: " + values);
        console.log("Selection: " + selection);
        console.log("Selection Args: " + selectionArgs);
        
        // Call the original update method
        return this.update(uri, values, selection, selectionArgs);
    };

    // Hook delete method
    ContentResolver.delete.overload('android.net.Uri', 'java.lang.String', '[Ljava.lang.String;').implementation = function(uri, selection, selectionArgs) {
        console.log("Deleting from ContentProvider: " + uri.toString());
        console.log("Selection: " + selection);
        console.log("Selection Args: " + selectionArgs);
        
        // Call the original delete method
        return this.delete(uri, selection, selectionArgs);
    };

    // -------------------------------

    // hook broadcast receivers

    // Get the BroadcastReceiver class
    var BroadcastReceiver = Java.use('android.content.BroadcastReceiver');

    // Hook onReceive
    BroadcastReceiver.onReceive.overload('android.content.Context', 'android.content.Intent').implementation = function(context, intent) {
        console.log("Broadcast received!");
        console.log("Intent Action: " + intent.getAction());
        
        // Optionally, log additional information about the intent
        var extras = intent.getExtras();
        if (extras != null) {
            var keys = extras.keySet();
            keys.forEach(function(key) {
                console.log(key + ": " + extras.get(key));
            });
        }
        
        // Call the original onReceive method
        return this.onReceive(context, intent);
    };

});
