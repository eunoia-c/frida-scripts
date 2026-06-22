// ANSI Color Constants for Terminal Output
const C_RESET = "\x1b[0m";
const C_GREEN = "\x1b[32m";
const C_YELLOW = "\x1b[33m";
const C_RED = "\x1b[31;1m"; // Bold Red
const C_CYAN = "\x1b[36m";

// Known noisy namespaces to ignore (reduces false positives)
const IGNORE_NAMESPACES = [
    "webview_flutter", // Ignores standard WebView SSL events
    "firebase_core", 
    "google_mobile_ads",
    "image_picker"
];

// Comprehensive list of security, anti-tamper, and environment checks
const SECURITY_KEYWORDS = [
    "security", "jailbreak", "root", "rasp", 
    "ssl", "pinning", "cert", "debug", 
    "emulator", "frida", "hook", "tamper", 
    "integrity", "safetynet", "playintegrity", 
    "biometric", "crypto", "magisk", "xposed", 
    "dexguard", "promon", "appdome", "guardsquare", // RASP Vendors
    "vpn", "proxy", "vpn_check" // Network checks
];

Java.perform(function() {
    console.log(C_CYAN + "[*] Intercepting Flutter Channel registrations on Android..." + C_RESET + "\n");

    // Helper function to check if a channel name matches security keywords
    function isTargetChannel(name) {
        let lowerName = name.toLowerCase();
        
        // Skip known noise first
        if (IGNORE_NAMESPACES.some(ignore => lowerName.includes(ignore))) {
            return false;
        }

        return SECURITY_KEYWORDS.some(keyword => lowerName.includes(keyword));
    }

    // 1. Hook MethodChannel (Standard Request/Response)
    try {
        var MethodChannel = Java.use('io.flutter.plugin.common.MethodChannel');
        
        MethodChannel.$init.overload('io.flutter.plugin.common.BinaryMessenger', 'java.lang.String').implementation = function(messenger, name) {
            if (isTargetChannel(name)) {
                console.log(C_RED + "[+] [MethodChannel] Registered: " + name + C_RESET);
                console.log(C_RED + "    [!] WARNING: Target Security Channel Identified." + C_RESET);
            } else {
                console.log(C_GREEN + "[+] [MethodChannel] Registered: " + C_RESET + name);
            }
            
            return this.$init(messenger, name);
        };
    } catch(err) {
        console.log(C_RED + "[-] MethodChannel class not found: " + err.message + C_RESET);
    }

    // 2. Hook EventChannel (Continuous Data Streams)
    try {
        var EventChannel = Java.use('io.flutter.plugin.common.EventChannel');
        
        EventChannel.$init.overload('io.flutter.plugin.common.BinaryMessenger', 'java.lang.String').implementation = function(messenger, name) {
            if (isTargetChannel(name)) {
                console.log(C_RED + "[+] [EventChannel] Registered: " + name + C_RESET);
                console.log(C_RED + "    [!] WARNING: Target Security Stream Identified." + C_RESET);
            } else {
                console.log(C_YELLOW + "[+] [EventChannel] Registered: " + C_RESET + name);
            }
            return this.$init(messenger, name);
        };
    } catch(err) {
        console.log(C_RED + "[-] EventChannel class not found." + C_RESET);
    }

    // 3. Hook BasicMessageChannel (Raw/Custom Messaging)
    try {
        var BasicMessageChannel = Java.use('io.flutter.plugin.common.BasicMessageChannel');
        
        BasicMessageChannel.$init.overload('io.flutter.plugin.common.BinaryMessenger', 'java.lang.String', 'io.flutter.plugin.common.MessageCodec').implementation = function(messenger, name, codec) {
            if (isTargetChannel(name)) {
                console.log(C_RED + "[+] [BasicMessageChannel] Registered: " + name + C_RESET);
                console.log(C_RED + "    [!] WARNING: Target Security Message Pipe Identified." + C_RESET);
            } else {
                console.log(C_CYAN + "[+] [BasicMessageChannel] Registered: " + C_RESET + name);
            }
            return this.$init(messenger, name, codec);
        };
    } catch(err) {
        console.log(C_RED + "[-] BasicMessageChannel class not found." + C_RESET);
    }
});
