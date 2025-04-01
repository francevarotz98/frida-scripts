/*
Purpose:
Bypass SSL pinning. There's also this script: https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
but it didn't always work.

Example Usage:
frida -U -N <package_name> -l .\bypass-ssl-pinning.js
*/

console.log("*******************************************************");
console.log("* Frida Bypassing SSL Pinning");
console.log("* Created by Francesco Varotto - GitHub: https://github.com/francevarotz98/");
console.log("*******************************************************");

Java.perform(function() {
    console.log("[+] Hooking SSL methods to bypass certificate validation");

    // Hook TrustManagerImpl (default Android SSL handler)
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] SSL Bypass: Skipping certificate validation for " + host);
        return untrustedChain;
    };

    // Hook okhttp3.CertificatePinner (used in modern Android apps)
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log("[+] SSL Bypass: Skipping OkHttp certificate pinning for " + hostname);
        return;
    };

    // Hook WebViewClient SSL error handler
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        console.log("[+] SSL Bypass: Ignoring WebView SSL error for " + view.getUrl());
        handler.proceed();
    };
});
