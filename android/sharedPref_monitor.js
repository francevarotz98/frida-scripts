/*
Monitor SharedPreferences used by the app.

Example Usage:
frida -U -N <package_name> -l .\sharedPref_monitor.js
*/

Java.perform(function() {
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');

    // Hook getString
    SharedPreferencesImpl.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        console.log('[SharedPreferences] getString("' + key + '", "' + defValue + '") => "' + result + '"');
        return result;
    };

    // Hook getInt
    SharedPreferencesImpl.getInt.overload('java.lang.String', 'int').implementation = function(key, defValue) {
        var result = this.getInt(key, defValue);
        console.log('[SharedPreferences] getInt("' + key + '", ' + defValue + ') => ' + result);
        return result;
    };

    // Hook getBoolean
    SharedPreferencesImpl.getBoolean.overload('java.lang.String', 'boolean').implementation = function(key, defValue) {
        var result = this.getBoolean(key, defValue);
        console.log('[SharedPreferences] getBoolean("' + key + '", ' + defValue + ') => ' + result);
        return result;
    };

    // Hook putString
    var EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    EditorImpl.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
        console.log('[SharedPreferences] putString("' + key + '", "' + value + '")');
        return this.putString(key, value);
    };

    // Hook putInt
    EditorImpl.putInt.overload('java.lang.String', 'int').implementation = function(key, value) {
        console.log('[SharedPreferences] putInt("' + key + '", ' + value + ')');
        return this.putInt(key, value);
    };

    // Hook putBoolean
    EditorImpl.putBoolean.overload('java.lang.String', 'boolean').implementation = function(key, value) {
        console.log('[SharedPreferences] putBoolean("' + key + '", ' + value + ')');
        return this.putBoolean(key, value);
    };

    // Optionally, hook commit and apply to see when changes are saved
    EditorImpl.commit.implementation = function() {
        console.log('[SharedPreferences] commit() called');
        return this.commit();
    };

    EditorImpl.apply.implementation = function() {
        console.log('[SharedPreferences] apply() called');
        this.apply();
    };
});
