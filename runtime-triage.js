// ANSI Colors for Terminal Output
const C_RESET = "\x1b[0m";
const C_GREEN = "\x1b[32m";
const C_YELLOW = "\x1b[33m";
const C_CYAN = "\x1b[36m";
const C_RED = "\x1b[31;1m";

function getAppInfo() {
    if (!Java.available) return;

    Java.perform(function() {
        try {
            console.log(C_CYAN + "\n[*] --- Application Identity ---" + C_RESET);
            const ActivityThread = Java.use('android.app.ActivityThread');
            const app = ActivityThread.currentApplication();
            
            if (app !== null) {
                const context = app.getApplicationContext();
                const pkgName = context.getPackageName();
                const pm = context.getPackageManager();
                const pi = pm.getPackageInfo(pkgName, 0);

                console.log(C_GREEN + "[+] Package Name : " + C_RESET + pkgName);
                console.log(C_GREEN + "[+] Version Name : " + C_RESET + pi.versionName.value);
                console.log(C_GREEN + "[+] Version Code : " + C_RESET + pi.versionCode.value);
            }
        } catch (e) {
            console.log(C_RED + "[-] Failed to retrieve App Info: " + e.message + C_RESET);
        }
    });
}

function fingerprintEngine() {
    console.log(C_CYAN + "\n[*] --- Engine Fingerprinting ---" + C_RESET);
    const modules = Process.enumerateModules();
    let detectedEngine = "Native (Java/Kotlin)";
    let indicators = [];

    modules.forEach(function(m) {
        let name = m.name.toLowerCase();
        if (name.includes("libflutter.so")) detectedEngine = "Flutter";
        else if (name.includes("libil2cpp.so") || name.includes("libunity.so")) detectedEngine = "Unity (IL2CPP)";
        else if (name.includes("libreactnativejni.so") || name.includes("libhermes.so")) detectedEngine = "React Native";
        else if (name.includes("libmonosgen-2.0.so")) detectedEngine = "Xamarin/Mono";
        else if (name.includes("libapp.so")) indicators.push("libapp.so (Dart AOT Payload)");
        else if (name.includes("libxwalkcore.so")) detectedEngine = "Cordova/Crosswalk";
    });

    console.log(C_GREEN + "[+] Detected Engine : " + C_RESET + detectedEngine);
    if (indicators.length > 0) {
        console.log(C_YELLOW + "[+] Key Modules     : " + C_RESET + indicators.join(", "));
    }
}

function hookSecretsAndNetwork() {
    if (!Java.available) return;

    Java.perform(function() {
        console.log(C_CYAN + "\n[*] --- Starting Secret & Network Listeners ---" + C_RESET);

        // 1. Hook Cryptographic Keys (AES/DES/Mac)
        try {
            const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
            SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
                // Convert byte array to hex string for readability
                let keyHex = [];
                for (let i = 0; i < keyBytes.length; i++) {
                    keyHex.push(('0' + (keyBytes[i] & 0xFF).toString(16)).slice(-2));
                }
                let keyString = keyHex.join('');
                
                console.log(C_RED + "[!] [CRYPTO] Key Initialized (" + algorithm + "): " + C_RESET + keyString);
                
                // Attempt to print as ASCII if possible
                try {
                    let asciiKey = Memory.readCString(this.getEncoded().buffer);
                    if (asciiKey && asciiKey.length > 3) {
                         console.log(C_RED + "    -> ASCII: " + asciiKey + C_RESET);
                    }
                } catch(e) {}

                return this.$init(keyBytes, algorithm);
            };
        } catch (e) {
            console.log(C_YELLOW + "[-] Could not hook SecretKeySpec." + C_RESET);
        }

        // 2. Hook Standard URL connections (Catches basic HTTP/REST calls)
        try {
            const URL = Java.use('java.net.URL');
            URL.$init.overload('java.lang.String').implementation = function(urlStr) {
                console.log(C_YELLOW + "[+] [NETWORK] URL Accessed: " + C_RESET + urlStr);
                return this.$init(urlStr);
            };
        } catch (e) {
             console.log(C_YELLOW + "[-] Could not hook java.net.URL." + C_RESET);
        }
        
        // 3. Hook SharedPreferences (Catches stored tokens/passwords)
        try {
            const SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
            SharedPreferencesImpl.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
                console.log(C_GREEN + "[+] [STORAGE] Pref Saved -> Key: " + C_RESET + key + C_GREEN + " | Value: " + C_RESET + value);
                return this.putString(key, value);
            };
        } catch(e) {
             console.log(C_YELLOW + "[-] Could not hook SharedPreferences." + C_RESET);
        }
    });
}

// Execute the triage functions
setTimeout(function() {
    getAppInfo();
    fingerprintEngine();
    hookSecretsAndNetwork();
}, 1000); // Slight delay to ensure context is fully loaded
