#!/bin/bash
# add to crontab like:
# @reboot sleep 60 && /persistent/custom_block/unifi_custom_blocklist.sh > /dev/null 2>&1 &
# Configuration variables
PROCESS_NAME="coredns"
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

mkdir -p "$TMP_FOLDER" > /dev/null 2>&1

# Function to handle logging
log_action() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $message" >> "$LOG_FILE"
}

# Default URL list content (omitted for brevity)
DEFAULT_URLS=$(cat << 'EOF'
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
EOF
)

# Parse command-line arguments for force
FORCE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--force)
            FORCE=1
            ;;
    esac
    shift
done

# Function to check if full update is needed
check_if_update_needed() {
    local lastupdatefile="$1"
    local update_delay_days="$2"
    local force="$3"

    if [[ -f "$lastupdatefile" ]]; then
        last_update_ts=$(cat "$lastupdatefile")
        now_ts=$(date +%s)

        # How many seconds must pass
        delay_seconds=$((update_delay_days * 86400))

        # If not forced and enough time has not passed → return 1 (skip full update)
        if [[ $force -eq 0 ]] && (( now_ts - last_update_ts < delay_seconds )); then
            return 1
        fi
    fi
    return 0
}

# Function to handle skipped update actions
handle_skipped_update() {
    local blocklistfile="$1"
    local tmpfile="$2"
    local update_delay_days="$3"

    #echo "$(date): Full Update skipped — last update was less than $update_delay_days days ago. Use -f or --force to override."
    if cmp -s "$blocklistfile" "$tmpfile" ; then
        echo "$(date): Custom Blocklist still in use, doing nothing." > /dev/null
    else
        sleep 10
        echo "$(date): Copying existing blocklist to $blocklistfile"
        sort "$blocklistfile" "$tmpfile" | uniq > "$MERGED_LIST_TMP"
        mv "$MERGED_LIST_TMP" "$blocklistfile"
        echo "$(date): Restarting CoreDNS to apply new blocklist file."
        pkill coredns
        # LOGGING ADDED HERE: Log when a merge/restart happened due to service restart
        log_action "Blocklist combined and CoreDNS restarted due to service start/restart (no full download)."
    fi
}

# Function to create default URL list if not exists
create_default_url_list() {
    local url_file_list="$1"
    local default_urls="$2"

    if [ ! -f "$url_file_list" ]; then
        echo "$(date): Using Default url list: $url_file_list"
        echo "$default_urls" > "$url_file_list"
    fi
}

# Function to fetch and merge sources (omitted for brevity)
fetch_and_merge_sources() {
    local blocklistfile="$1"
    local url_file_list="$2"
    local tmpfile="$3"

    touch "$tmpfile"
    {
      # existing file
      cat "$blocklistfile"

      # URL sources from file
      while IFS= read -r url; do
        # Trim leading/trailing whitespace
        url="$(echo "$url" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

        # Skip empty or commented lines
        [ -z "$url" ] && continue
        case "$url" in
          \#*|\!* ) continue ;;
        esac
        # Fetch & clean
        curl -s "$url" \
          | grep -v '^[!#]' \
          | sed '/^\s*$/d' \
          | sed 's/^||//' \
          | sed 's/\^$//'

      done < "$url_file_list"
    } | sort -u \
      | grep -Ev '^\.' \
      | grep -Ev '^\*-' \
      | grep -Ev '^-' \
      | grep -Ev '^/' \
      | grep -Ev '\*' \
      | grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$' \
      > "$tmpfile"

    echo "$(date): Combined List cleanup."
}

# Function to apply removal rules using AWK (omitted for brevity)
apply_removal_rules() {
    local tmpfile="$1"
    local removefile="$2"

    awk -v patfile="$removefile" '
    BEGIN {
        # load removal rules
        while ((getline rule < patfile) > 0) {
            # skip empty lines / pure whitespace
            if (rule ~ /^[ \t]*$/) continue

            # Escape regex special chars except *
            gsub(/[][(){}+?.\\^$|]/, "\\\\&", rule)

            # Convert * into .*
            gsub(/\*/, ".*", rule)

            patterns[++n] = "^" rule "$"
        }
    }

    {
        drop = 0
        # Check against each pattern
        for (i = 1; i <= n; i++) {
            if ($0 ~ patterns[i]) {
                drop = 1
                break
            }
        }
        if (!drop) print
    }
    ' "$tmpfile" > "${tmpfile}.filtered"
}

# Function to finalize the blocklist
finalize_blocklist() {
    local tmpfile="$1"
    local blocklistfile="$2"
    local lastupdatefile="$3"

    mv "${tmpfile}.filtered" "$tmpfile"
    cp "$tmpfile" "$blocklistfile"

    echo "$(date): Restarting CoreDNS to apply new blocklist file"
    pkill coredns
    
    local line_count="$(wc -l < $blocklistfile)"
    local size="$(du -sh $blocklistfile | awk '{print $1}')"

    # LOGGING ADDED HERE: Log when a full update (download) was completed
    log_action "Blocklist full update completed. Size: $size, Lines: $line_count"
    
    echo "$(date): Blocklist created at: $blocklistfile with size $size and $line_count lines"
}

# Main function to update the blocklist
update_blocklist() {
    local force="$1"

    if check_if_update_needed "$LAST_UPDATE_FILE" "$UPDATE_DELAY_DAYS" "$force"; then
        create_default_url_list "$URL_FILE_LIST" "$DEFAULT_URLS"
        fetch_and_merge_sources "$BLOCKLIST_FILE" "$URL_FILE_LIST" "$TMP_FILE"
        apply_removal_rules "$TMP_FILE" "$REMOVE_FILE"
        finalize_blocklist "$TMP_FILE" "$BLOCKLIST_FILE" "$LAST_UPDATE_FILE"
        # Save update timestamp after full success.
        date +%s > "$LAST_UPDATE_FILE"
    else
        handle_skipped_update "$BLOCKLIST_FILE" "$TMP_FILE" "$UPDATE_DELAY_DAYS"
    fi
}

echo "$(date): Starting PID check..."

while true; do
    # Load last PID from file
    LAST_PID=""
    [[ -f "$PID_FILE" ]] && LAST_PID=$(cat "$PID_FILE")

    # Get current PID
    CURRENT_PID=$(pgrep -f "$PROCESS_NAME")

    if [[ -n "$CURRENT_PID" ]]; then
        # Process is running
        if [[ "$CURRENT_PID" != "$LAST_PID" ]]; then
            echo "$(date): PID changed: $LAST_PID -> $CURRENT_PID"
        fi
        
        # FIX: Call update_blocklist unconditionally when CoreDNS is running.
        # The function's internal logic handles the time-based check.
        # This ensures the list is updated every N days, even if CoreDNS
        # doesn't restart.
        #echo "$(date): Checking for Blocklist update..."
        update_blocklist "$FORCE"

        # Always update PID file if process is running and new PID is found
        # (This is mainly for the initial run or if CoreDNS was just restarted)
        sleep 2
        CURRENT_PID=$(pgrep -f "$PROCESS_NAME")
        echo "$CURRENT_PID" > "$PID_FILE"
        
    else
        # Process not running
        #echo "$(date): $PROCESS_NAME not running!"

        # Reset PID file
        echo "" > "$PID_FILE"
    fi

    sleep $CHECK_INTERVAL
done
