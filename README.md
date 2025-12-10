# !!! By enabling and modifying UNIFI OS you may loose your warranty !!!
********************************* NOTICE **********************************
* By logging in to, accessing, or using any Ubiquiti product, you are     *
* signifying that you have read our Terms of Service (ToS) and End User   *
* License Agreement (EULA), understand their terms, and agree to be       *
* fully bound to them. The use of CLI (Command Line Interface) can        *
* potentially harm Ubiquiti devices and result in lost access to them and *
* their data. By proceeding, you acknowledge that the use of CLI to       *
* modify device(s) outside of their normal operational scope, or in any   *
* manner inconsistent with the ToS or EULA, will permanently and          *
* irrevocably void any applicable warranty.                               *
***************************************************************************


## ADblock/Tracking... blocking script for Unifi OS ( tested on UDR 7)
- first enable SSH to the router ( check documentation for your device to find how)
- then ssh to the device ( user is usually root and password what you set in web ui)
- for me the OS was Debian 11, so i could just install nano and put it in, I saved it in `/persistent` folder
- you could put it to `/sdcard1` or whereever you want...
- then with `crontab -e` what more then likely using `vi` editor add line like:
`@reboot sleep 60 && /persistent/custom_block/unifi_custom_blocklist.sh > /dev/null 2>&1 &`
- the `sleep 60` can be adjusted, if it is not starting, to give enough time to OS to start
- depending on how much URLS and their content it can take 2-4 minutes to finish the downloading
- in the script you can adjust how often it will redownloads the data default `UPDATE_DELAY_DAYS=3`
- it should download also anytime the `/tmp` folder is cleared in case you use that for temporary data storage.
- it monitors `coredns` what is then giving unifi FW info if the domain should be blocked or no
- you could add some whitelists too, but i do that via web ui, as those are just few
- if you try to pass all those domains via web ui it crashes ( about 500k for my selection)

## Default variables:
```bash
PROCESS_NAME="coredns"  # Do not change, unless they change in future the app for it.   
TMP_FOLDER="/tmp/custom_block"
PID_FILE="${TMP_FOLDER}/coredns_last.pid"
CHECK_INTERVAL=5
UPDATE_DELAY_DAYS=3
TMP_FILE="${TMP_FOLDER}/combined-blocklist.txt"
LAST_UPDATE_FILE="${TMP_FOLDER}/last_update.txt"
URL_FILE_LIST="${TMP_FOLDER}/urllist.txt"
BLOCKLIST_FILE="/run/utm/domain_list/domainlist_0.list"
REMOVE_FILE="/run/utm/domain_list/domainlist_1.list"
MERGED_LIST_TMP="${TMP_FOLDER}/mergedlist.txt"
# NEW: Log file location
LOG_FILE="${TMP_FOLDER}/custom_list.log"
```
## Default URL lists:
```bash
https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt
https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt
https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt
https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt
https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt
https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt
https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt
https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt
https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt
https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt
https://v.firebog.net/hosts/Prigent-Crypto.txt
https://phishing.army/download/phishing_army_blocklist_extended.txt
https://v.firebog.net/hosts/static/w3kbl.txt
```
