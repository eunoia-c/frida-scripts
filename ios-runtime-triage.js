// ANSI Colors for Terminal Output
const C_RESET = "\x1b[0m";
const C_GREEN = "\x1b[32m";
const C_YELLOW = "\x1b[33m";
const C_CYAN = "\x1b[36m";
const C_RED = "\x1b[31;1m";

function getAppInfo() {
    if (!ObjC.available) {
        console.log(C_RED + "[-] Objective-C Runtime unavailable." + C_RESET);
        return;
    }

    try {
        console.log(C_CYAN + "\n[*] --- Application Identity ---" + C_RESET);
        const bundle = ObjC.classes.NSBundle.mainBundle();
        const bundleId = bundle.bundleIdentifier().toString();
        const infoDict = bundle.infoDictionary();
        
        const version = infoDict.objectForKey_("CFBundleShortVersionString") ? infoDict.objectForKey_("CFBundleShortVersionString").toString() : "Unknown";
        const build = infoDict.objectForKey_("CFBundleVersion") ? infoDict.objectForKey_("CFBundleVersion").toString() : "Unknown";

        console.log(C_GREEN + "[+] Bundle ID    : " + C_RESET + bundleId);
        console.log(C_GREEN + "[+] Version Name : " + C_RESET + version);
        console.log(C_GREEN + "[+] Build Number : " + C_RESET + build);
    } catch (e) {
        console.log(C_RED + "[-] Failed to retrieve App Info: " + e.message + C_RESET);
    }
}

function fingerprintEngine() {
    console.log(C_CYAN + "\n[*] --- Engine Fingerprinting ---" + C_RESET);
    const modules = Process.enumerateModules();
    let detectedEngine = "Native (Objective-C/Swift)";
    let indicators = [];

    modules.forEach(function(m) {
        let name = m.name.toLowerCase();
        if (name.includes("flutter")) detectedEngine = "Flutter";
        else if (name.includes("unityframework") || name.includes("il2cpp")) detectedEngine = "Unity (IL2CPP)";
        else if (name.includes("hermes")) detectedEngine = "React Native (Hermes)";
        else if (name.includes("libjsc") && detectedEngine !== "React Native (Hermes)") detectedEngine = "React Native (JSC)";
        else if (name.includes("libmono")) detectedEngine = "Xamarin/Mono";
        else if (name.includes("cordova")) detectedEngine = "Cordova";
    });

    console.log(C_GREEN + "[+] Detected Engine : " + C_RESET + detectedEngine);
    if (indicators.length > 0) {
        console.log(C_YELLOW + "[+] Key Modules     : " + C_RESET + indicators.join(", "));
    }
}

function hookSecretsAndNetwork() {
    console.log(C_CYAN + "\n[*] --- Starting Secret & Network Listeners ---" + C_RESET);

    // 1. Hook Cryptographic Keys (CommonCrypto - CCCrypt)
    const CCCryptPtr = Module.findExportByName(null, "CCCrypt");
    if (CCCryptPtr) {
        Interceptor.attach(CCCryptPtr, {
            onEnter: function(args) {
                const keyPtr = args[3];
                const keyLen = args[4].toInt32();
                
                if (keyLen > 0 && keyLen <= 64) {
                    try {
                        const keyBytes = Memory.readByteArray(keyPtr, keyLen);
                        const keyHex = Array.from(new Uint8Array(keyBytes))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join('');
                            
                        console.log(C_RED + "[!] [CRYPTO] CCCrypt Key Initialized (Len: " + keyLen + "): " + C_RESET + keyHex);
                        
                        // Attempt ASCII extraction
                        const asciiKey = Memory.readCString(keyPtr);
                        if (asciiKey && asciiKey.length >= 3) {
                            console.log(C_RED + "    -> ASCII: " + asciiKey + C_RESET);
                        }
                    } catch (e) {}
                }
            }
        });
    } else {
        console.log(C_YELLOW + "[-] Could not find CCCrypt." + C_RESET);
    }

    if (!ObjC.available) return;

    // 2. Hook Standard URL connections
    try {
        const NSURL = ObjC.classes.NSURL;
        Interceptor.attach(NSURL["- initWithString:"].implementation, {
            onEnter: function(args) {
                if (args[2]) {
                    const urlStr = new ObjC.Object(args[2]).toString();
                    console.log(C_YELLOW + "[+] [NETWORK] URL Accessed: " + C_RESET + urlStr);
                }
            }
        });
    } catch (e) {
        console.log(C_YELLOW + "[-] Could not hook NSURL." + C_RESET);
    }
    
    // 3. Hook NSUserDefaults (Catches stored tokens/passwords)
    try {
        const NSUserDefaults = ObjC.classes.NSUserDefaults;
        Interceptor.attach(NSUserDefaults["- setObject:forKey:"].implementation, {
            onEnter: function(args) {
                if (args[2] && args[3]) {
                    const val = new ObjC.Object(args[2]).toString();
                    const key = new ObjC.Object(args[3]).toString();
                    // Filter out Apple/System noise
                    if (!key.startsWith("Apple") && !key.startsWith("NS")) {
                        console.log(C_GREEN + "[+] [STORAGE] Pref Saved -> Key: " + C_RESET + key + C_GREEN + " | Value: " + C_RESET + val);
                    }
                }
            }
        });
    } catch(e) {
        console.log(C_YELLOW + "[-] Could not hook NSUserDefaults." + C_RESET);
    }
}

// Execute the triage functions
setTimeout(function() {
    getAppInfo();
    fingerprintEngine();
    hookSecretsAndNetwork();
}, 1000); // Slight delay to ensure context is fully loaded
