# frida-scripts
collection of frida scripts for mobile app pentesting and security research.

#### Usage
Use the runtime triage scripts to view information of the application if you don't have decompilation tool such as apktool or jadx.
```
frida -U -f com.target.app -l triage_recon.js //change the app and the runtime script based on the app youre using
```

#### Expected Output
```
[*] --- Application Identity --- (Package Name, Version)
[+] Package Name : com.pany.bankingapp
[+] Version Name : 4.0.9
[+] Version Code : 400011
[*] --- Engine Fingerprinting --- (Detected Frameworks)
[+] Detected Engine : Flutter
[+] Key Modules     : libapp.so (Dart AOT Payload)
[*] --- Starting Secret & Network Listeners --- (Live Crypto Keys, URLs, and Stored Prefs)
[+] [STORAGE] Pref Saved -> Key: |T|812270506136|* | Value: {"token":"cdrLga2QVv6qMJsBnzAcXvafbLd:APA91s1_bH8qzWXPtd5aSsndMVFQA7qskyyAanwdJDASfWtsseQAS75TOqlWTFGtfr7Aq0YZbzHu6b6wuyIEBIYB_9Jw-9lzgJE7Q_aJy3Xe7vQuEuAAOE0Lr7bNHceOfwSQ","appVersion":"11","timestamp":1782131146969}
[+] [STORAGE] Pref Saved -> Key: flutter.status | Value: 0
```
