# frida-scripts
collection of frida scripts for mobile app pentesting and security research.

### Usage
Use the runtime triage scripts to view information of the application if you don't have decompilation tool such as apktool or jadx.
```
frida -U -f com.target.app -l triage_recon.js //change the app and the runtime script based on the app youre using
```
