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

function monitoriOSFlutterChannels() {
    if (!ObjC.available) {
        console.log(C_RED + "[-] Objective-C Runtime unavailable. Not an iOS environment." + C_RESET);
        return;
    }

    console.log(C_CYAN + "[*] Intercepting Flutter Channel registrations on iOS..." + C_RESET + "\n");

    // Helper function to check if a channel name matches security keywords
    function isTargetChannel(name) {
        if (!name) return false;
        let lowerName = name.toLowerCase();
        
        // Skip known noise first
        if (IGNORE_NAMESPACES.some(ignore => lowerName.includes(ignore))) {
            return false;
        }

        return SECURITY_KEYWORDS.some(keyword => lowerName.includes(keyword));
    }

    // 1. Hook MethodChannel (Standard Request/Response)
    if (ObjC.classes.FlutterMethodChannel) {
        try {
            var methodChannelInit = ObjC.classes.FlutterMethodChannel["+ methodChannelWithName:binaryMessenger:"];
            Interceptor.attach(methodChannelInit.implementation, {
                onEnter: function(args) {
                    // args[2] is the 'name' parameter in Objective-C methods
                    var channelName = new ObjC.Object(args[2]).toString();
                    
                    if (isTargetChannel(channelName)) {
                        console.log(C_RED + "[+] [MethodChannel] Registered: " + channelName + C_RESET);
                        console.log(C_RED + "    [!] WARNING: Target Security Channel Identified." + C_RESET);
                    } else {
                        console.log(C_GREEN + "[+] [MethodChannel] Registered: " + C_RESET + channelName);
                    }
                }
            });
        } catch(err) {
            console.log(C_RED + "[-] Error hooking FlutterMethodChannel: " + err.message + C_RESET);
        }
    } else {
        console.log(C_RED + "[-] FlutterMethodChannel class not found." + C_RESET);
    }

    // 2. Hook EventChannel (Continuous Data Streams)
    if (ObjC.classes.FlutterEventChannel) {
        try {
             var eventChannelInit = ObjC.classes.FlutterEventChannel["+ eventChannelWithName:binaryMessenger:"];
             Interceptor.attach(eventChannelInit.implementation, {
                 onEnter: function(args) {
                     var channelName = new ObjC.Object(args[2]).toString();
                     
                     if (isTargetChannel(channelName)) {
                         console.log(C_RED + "[+] [EventChannel] Registered: " + channelName + C_RESET);
                         console.log(C_RED + "    [!] WARNING: Target Security Stream Identified." + C_RESET);
                     } else {
                         console.log(C_YELLOW + "[+] [EventChannel] Registered: " + C_RESET + channelName);
                     }
                 }
             });
        } catch(err) {
            console.log(C_RED + "[-] Error hooking FlutterEventChannel: " + err.message + C_RESET);
        }
    }

    // 3. Hook BasicMessageChannel (Raw/Custom Messaging)
    if (ObjC.classes.FlutterBasicMessageChannel) {
        try {
            var basicChannelInit = ObjC.classes.FlutterBasicMessageChannel["+ messageChannelWithName:binaryMessenger:codec:"];
            Interceptor.attach(basicChannelInit.implementation, {
                onEnter: function(args) {
                    var channelName = new ObjC.Object(args[2]).toString();
                    
                    if (isTargetChannel(channelName)) {
                        console.log(C_RED + "[+] [BasicMessageChannel] Registered: " + channelName + C_RESET);
                        console.log(C_RED + "    [!] WARNING: Target Security Message Pipe Identified." + C_RESET);
                    } else {
                        console.log(C_CYAN + "[+] [BasicMessageChannel] Registered: " + C_RESET + channelName);
                    }
                }
            });
        } catch(err) {
            console.log(C_RED + "[-] Error hooking FlutterBasicMessageChannel: " + err.message + C_RESET);
        }
    }
}

// Execute the monitoring
monitoriOSFlutterChannels();
