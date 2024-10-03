#!/bin/bash
# jshunter.sh
# Find linked and unlinked JS files for a given target.
# (c) garthoid  2024
# contact: garthoid@gmail.com
# Dependencies:
# Gau
# Hakwarler
# SecLists
# jq
# httpx
#set -euo pipefail


# Set up the trap to catch the INT signal (Ctrl+C).
# Sets up a trap for the SIGINT signal, which is triggered when the user presses Ctrl+C allowng 
# you to define a custom behavior when the script receives this interrupt signal instead of terminating.
trap ctrl_c INT


# Tidy
# Trap attempts to CTRL-C out of the script in order to tidy up working directories.
ctrl_c() {
    echo "[^]interrupt detected, doing cleanup and exiting."
    do_cleanup
    exit 0
}
do_cleanup() {
    rm -rf $TMPDIR/*.txt
    rm -rf $TMPDIR/*.json
}


banner() {
echo "   _      _                                  "
echo "  (_)    | |                _                "
echo "   _  ___| | _  _   _ ____ | |_  ____  ___  _"
echo "  | |/___) || \| | | |  _ \|  _)/ _  )/ ___) "
echo "  | |___ | | | | |_| | | | | |_( (/ /| |     "
echo " _| (___/|_| |_|\____|_| |_|\___)____)_|     "
echo "(__/ @garthoid 2024                        "
echo "                                             "
}


spinner() {
    if [ "$silent" = "false" ]; then
        local pid=$1
        local delay=0.1
        local spinstr='|/-\'

        while [ "$(ps -p $pid | grep $pid)" ]; do
            for i in $(seq 0 3); do
                printf "\r[%c]  " "${spinstr:$i:1}"  # Update spinner in place
                sleep $delay
            done
        done
        printf "\r    \r"  # Clear the spinner after the background task is done
    fi
}

# Display usage information.
usage() {
    echo "Usage: ./jshunter.sh [-hs] [-d SecLists root Directory] [-j wordlist] [-a] [-t Target URL]"
    echo "       -h: This help page."
    echo "       -s: Silent output - No banner, no progress, only urls."
    echo "       -d: SecLists Root Directory."
    echo "       -j: JS filename wordlist."
    echo "       -a: Use OpenAI for fuzzing/halicinating wordlist entries."
}

log() {
    local msg=$1
    if [ "$silent" = "false" ]; then
        echo "[*] $msg"
    else
        echo "[*] $msg" >> $LOGFILE
    fi
}
logfile() {
    local file=$1
    if [ "$silent" = "false" ]; then
        cat "$file"
    else
        cat "$file" >> $LOGFILE
    fi
}


# Function to check if the URL is well-formed (supports HTTP/HTTPS).
validate_url() {
    log "valiate_url $1"
    local url=$1
    # Regex to match a well-formed HTTP or HTTPS URL
    regex="^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/[a-zA-Z0-9._~:\/?#[\]@!$&'()*+,;=%-]*)?$"

    if [[ $url =~ $regex ]]; then
        return 0
    else
        return 1
    fi
}

# Call the gau for information on known urls for the target. It returns the number of urls found.
# Store all results in a file and then filter out specific JS results into another file.
running_gau() {
    local target=$1
    echo "$target" | gau | unfurl format "%s://%d%:%P%p" | sort -u > $GAU_RESULTS
    cat  "$GAU_RESULTS" | grep -iE "\.js$" | sort -u > $GAU_JS_RESULTS
}

# Call hakrawler to spider target and extract linked directories and JS files.
# Store all results in a file and then filter out specific JS results into another file.
running_hakrawler() {
    local target=$1
    echo $target | hakrawler -insecure > $HAKRAWLER_RESULTS
    cat $HAKRAWLER_RESULTS | unfurl format "%s://%d%:%P%p" | grep -iE "\.js$" | sort -u > $HAKRAWLER_JS
}

# A function to generate renamed JS file wordlist based on found JS files. It uses a pre-canned
# wordlist. The first parameter is the name of the file containing known JS filenames. The new
# wordlist will be in a file identified by KNOWN_JS_FILES_RENAME.
generate_renamed_js_wordlist() {
    # This should probably be in a file. This is just a quick example of using 
    # an array of extensions.
    extension_array=(".bak" ".backup" ".old" ".orig" ".tmp" ".copy" ".sav" ".prev" ".1" ".2" ".3" ".~" ".bk" ".sbk" ".ibk" ".001" ".002")
    local known_js_filenames=$1
    cat $known_js_filenames | while read jsname; do
        for element in "${extension_array[@]}"; do
            local js_filename="$jsname$element"
            echo $js_filename >> $KNOWN_JS_FILES_RENAME
        done
    done
}

# This function fuzzes known linked directories on a target website with a given wordlist.
# The function takes two parameters, a wordlist, and a filename to output results. The 
# function uses KNOWN_JS_DIRS_SORTED as a source of known target paths. As there may be 
# multiple target directories the results of each fuzzed directory is added a numbered file
# These numbered files are combined.
fuzz_known_directories() {

    wordlist=$1
    outputfile=$2


    cat $KNOWN_JS_DIRS_SORTED | while read jsdir; do
        log "Running FFUF on $jsdir with $wordlist"

        tmp_output_file="$outputfile-tmp.json"
        ffuf -s \
            -w $wordlist \
            -u $jsdir/FUZZ \
            -mc 200,304 \
            -o $tmp_output_file \
            -t 100 > /dev/null 

        # Extract results array from temporary output and test for contents.
        # Trim leading and trailing spaces from the variable. Append valid 
        # contents to final output file.
        results=($(jq -r '.results[]' $tmp_output_file))
        for i in "${!results[@]}"; do
            trimmed_variable="$(echo -e "${i}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            if [ -z "$trimmed_variable" ]; then
                echo $trimmed_variable >> $outputfile
            fi
        done

    done
}

# This function genereates a wordlist based on a prompt and known JS filenames.
# The resulting wordlist is stored in a file identied by $KNOWN_JS_FILES_AI_RENAME.
# The function accests as input the name of a file containing known JS filesnames.
# This file contains the name of the files and not their path.
generate_renamed_js_ai_wordlist() {

    prompt_static="Provide a list of 50 potential filenames that a developer or \
            administrator would commonly rename the file to using the following \
            filename as a base. Provide results in a comma separated list. Do not \
            number entries."

    known_js_files_file=$1
    log "ai names source: $known_js_files_file"

    # For each filename in known_js_files_file extract the name and prompt
    # AI for possible alternate renames.
    cat $known_js_files_file | while read jsname; do
        prompt="$prompt_static $jsname"

        # Construct the API request using curl.
        response=$(curl -sS -D - https://api.openai.com/v1/chat/completions \
            -w "\n%{http_code}" \
            -H "Content-Type: application/json"  \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            -d '{
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "'"$prompt"'"}]
            }' 
        )
        headers=$(echo "$response" | sed -n '/^\r$/q;p')
        body=$(echo "$response" | sed -n '/^\r$/,$p' | tail -n +2)
        status_code=$(echo "$response" | tail -n 1)

        # Extract HTTP status code to determine if we can continue 
        # process or exit processing this feature.
        if [ "$status_code" -ne 200 ]; then
            log "Error in OpenAI call"
            return 1
        fi
        
        # For some reason the response body has a "200" at the end. Trim
        # that so JQ does not have a hairball with it.
        var3="${body%\}*}"
        trimmed_body="$var3}"
        
        # Extract the message content from the JSON body. This will be a string
        # of values separated by ,
        completion=$(echo "$trimmed_body" | jq -r '.choices[0].message.content')

        # Replace the , with spc and trim front and tail.
        cleaned_string=$(echo "$completion" | sed 's/^"//; s/"$//') # remove lead/trail spaces

        # Convert string into an array.
        IFS=',' read -r -a string_array <<< "$cleaned_string"

        # We want to drop these values into a file to behave as a wordlist. The file is 
        # identified by KNOWN_JS_FILES_AI_RENAME.
        for element in "${string_array[@]}"; do
            echo $element >> $KNOWN_JS_FILES_AI_RENAME
        done
    done
    aicount="$(wc -l $KNOWN_JS_FILES_AI_RENAME | sed -e 's/^[[:space:]]*//' | cut -d " " -f 1)"
    log "AI found $aicount potential names."
    return 0
}

# Process command line parameters.
silent=false
target=null
SEC_LISTS_ROOT=null
while getopts ":ahst:d:" opt; do
    case $opt in
        h)
            usage
            exit 0
            ;;
        s)
            silent=true
            ;;
        j)
            usage
            exit 1
            ;;
        d)
            SEC_LISTS_ROOT=$OPTARG
            ;;
        t)
            url=$OPTARG
            ;;
        a)
            brain=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            exit 0
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            usage
            exit 0
            ;;
      esac
done

# Display greeting banner if silent is off.
if [ "$silent" = "false" ]; then
    banner
fi
log  "Silent mode turned off"


# Process the target URL. Ensure its there plus ensure its well formed.
if [ "$url" = "null" ]; then
    log "target missing"
    usage
    exit 1
fi

# Ensure SecLists root is set. And has the contents we need.
log "SecLists Root testing"
if [ "$SEC_LISTS_ROOT" = "null" ]; then
    log "SecLists Root directory not set"
    usage
    exit 1
else
    log "SecLists Root directory set to $SEC_LISTS_ROOT"
    FILE="$SEC_LISTS_ROOT/Discovery/Web-Content/SVNDigger/cat/Language/js.txt"
    if [ -e "$FILE" ]; then
        log "SecLists Root directory valid"
    else
        log "SecLists Root directory is not valid"
        usage
            exit 1
    fi
fi


# Check if AI mode turned on.
if [ "$brain" = "true" ]; then
    log "AI mode Turned on"
else
        log "AI mode Turned off"
fi

# Check for OPEN_API_KEY from environment variable.
# Replace 'ENV_VAR' with the name of your environment variable
if [ -z "${OPENAI_API_KEY}" ]; then
    log "OPENAI_API_KEY is not set or is empty"
    if [ "$brain" = "true" ]; then
        log "AI mode needs OPENAI_API_KEY set"
        exit 1
    fi
else
    log "OPENAI_API_KEY is set"
fi


# Process target and confirm accessible.
target=`echo "$url" | unfurl format "%s://%d%:%P"`
domain=`echo "$url" | unfurl domain`
log "target is $target"
log "domain is $domain"
log "Checking if $target is responsive"
target_exists=$(httpx -u $target -status-code -silent -no-color | cut -d " " -f2)
if [ "$target_exists" = "[200]" ]; then
    log "$target is reachable"
else
    log "$target is not reachable"
        exit 1
fi


# Determine the current working directory.
#DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 &&pwd)"
#log "Current working directory is $DIR"


# Set a temporary working directory.
TMPDIR="/tmp/jshunter/$domain"

log "Working directory is $TMPDIR"
if [ -e "$TMPDIR" ]; then
    CURRENT_DATE=$(date +"%d-%m-%Y")
    NEW_DIR_NAME="${TMPDIR}_${CURRENT_DATE}"
    mv "$TMPDIR" "$NEW_DIR_NAME"
fi
mkdir -p $TMPDIR
LOGFILE=$TMPDIR/jshunter.log

# General Gau Results.
GAU_RESULTS=$TMPDIR/gau-results.txt
GAU_JS_RESULTS=$TMPDIR/gau-js-results.txt
GAU_JS_FILES=$TMPDIR/gau-js-files.txt
GAU_JS_FILES_SORTED=$TMPDIR/gau-js-files-sorted.txt
GAU_JS_DIRS=$TMPDIR/gau-js-dirs.txt
GAU_JS_DIRS_SORTED=$TMPDIR/gau-js-dirs-sorted.txt

# Hakwarler data files.
HAKRAWLER_RESULTS=$TMPDIR/hakrawler-results.txt
HAKRAWLER_JS=$TMPDIR/hakrawler-js.txt
HAKRAWLER_JS_FILES=$TMPDIR/hakrawler-js-files.txt
HAKRAWLER_JS_FILES_SORTED=$TMPDIR/hakrawler-js-files-sorted.txt
HAKRAWLER_JS_DIRS=$TMPDIR/hakrawler-js-dirs.txt
HAKRAWLER_JS_DIRS_SORTED=$TMPDIR/hakrawler-js-dirs-sorted.txt

# Known JS Files and Directories.
KNOWN_JS_FILES=$TMPDIR/known-js-files.txt
KNOWN_JS_FILES_SORTED=$TMPDIR/known-js-files-sorted.txt
KNOWN_JS_FILES_RENAME=$TMPDIR/known-js-files-renamed.txt
KNOWN_JS_FILES_RENAME_FOUND=$TMPDIR/known-js-files-renamed-found.txt
KNOWN_JS_FILES_AI_RENAME=$TMPDIR/known-js-files-ai-renamed.txt
KNOWN_JS_DIRS=$TMPDIR/known-js-dirs.txt
KNOWN_JS_DIRS_SECLIST_FOUND=$TMPDIR/known-js-dirs-seclist-found.txt
KNOWN_JS_DIRS_SORTED=$TMPDIR/known-js-dirs-sorted.txt
KNOWN_DIRS=$TMPDIR/known-dirs.txt

FFUF_SECLISTS_JS=$TMPDIR/ffuf-seclist-js.txt
FFUF_PRECANNED_JS=$TMPDIR/ffuf-precanned-js.txt
FFUF_AI_JS=$TMPDIR/ffuf-ai-js.txt
FFUF_FINAL_RESULTS=$TMPDIR/ffuf-final-results.txt

# Wordlists.
WLDIR="${DIR}/wordlists"
wordlist="$WLDIR/scripthunter-wordlist.txt"
jsdirwl="$WLDIR/jsdirs-common.txt"
aggr="$WLDIR/aggregated.txt"


# Run Gau to determine known urls from waybackmachine, AlienVault's OpenThreatExchange, 
# CommonCrawl, and URLScan. Then add the filenames to known filenames list, and the paths
# to the known paths list.
log "Running GAU"
running_gau "$target" &
task_pid=$!
spinner $task_pid
gaucount="$(wc -l $GAU_JS_RESULTS | sed -e 's/^[[:space:]]*//' | cut -d " " -f 1)"
log "Gau found $gaucount scripts"
cat $GAU_JS_RESULTS | while read gaudir; do
    filename=$(basename $gaudir)
    echo $filename >> $GAU_JS_FILES
    directory=$(dirname $gaudir)
    echo $directory >> $GAU_JS_DIRS
done
# Sort for uniqueness all JS dirs found by Gau.
cat $GAU_JS_DIRS | sort -u | while read sortdir; do
    echo $sortdir >> $GAU_JS_DIRS_SORTED
done
# Sort for uniqueness all JS files found by Gau.
cat $GAU_JS_FILES | sort -u | while read sortdir; do
    echo $sortdir >> $GAU_JS_FILES_SORTED
done


# Run hakrawler to spider the site and find paths and JS Files for linked content. 
# We will add findings to known files and known directories files.
log "Running hakrawler"
running_hakrawler "$target" &
task_pid=$!
spinner $task_pid
hakcount="$(wc -l $HAKRAWLER_JS | sed -e 's/^[[:space:]]*//' | cut -d " " -f 1)"
log "HAKRAWLER found $hakcount scripts!"
cat $HAKRAWLER_JS | while read hakdir; do
    filename=$(basename $hakdir)
    echo $filename >> $HAKRAWLER_JS_FILES
    directory=$(dirname $hakdir)
    echo $directory >> $HAKRAWLER_JS_DIRS
done
# Sort for uniqueness all JS dirs found by Hakrawler.
cat $HAKRAWLER_JS_DIRS | sort -u | while read sortdir; do
    echo $sortdir >> $HAKRAWLER_JS_DIRS_SORTED
done
# Sort for uniqueness all JS files found by Hakrawler.
cat $HAKRAWLER_JS_FILES | sort -u | while read sortdir; do
    echo $sortdir >> $HAKRAWLER_JS_FILES_SORTED
done

# Combine known JS directories into a single sorted file identified by 
# KNOWN_JS_DIRS_SORTED.
cat $GAU_JS_DIRS_SORTED > $KNOWN_JS_DIRS
cat $HAKRAWLER_JS_DIRS_SORTED >> $KNOWN_JS_DIRS
cat $KNOWN_JS_DIRS | sort -u | while read sortdir; do
    echo $sortdir >> $KNOWN_JS_DIRS_SORTED
done
known_js_dirs_count="$(wc -l $KNOWN_JS_DIRS_SORTED | sed -e 's/^[[:space:]]*//' | cut -d " " -f 1)"
log "JSHunter has found $known_js_dirs_count directories containing linked JS content."


# Combine known JS files into a single sorted file identified by 
# KNOWN_JS_FILES_SORTED.
cat $GAU_JS_FILES_SORTED > $KNOWN_JS_FILES
cat $HAKRAWLER_JS_FILES_SORTED >> $KNOWN_JS_FILES
cat $KNOWN_JS_FILES | sort -u | while read sortdir; do
    echo $sortdir >> $KNOWN_JS_FILES_SORTED
done


# Use FFUF to fuzz known JS directories for other JS Files based on a SecList wordlist. 
# Parameters are: path to the wordlist and path to output file.
log "Creating output file for SecList fuzzing: $FFUF_SECLISTS_JS"
touch "$FFUF_SECLISTS_JS"
fuzz_known_directories \
        "$SEC_LISTS_ROOT/Discovery/Web-Content/SVNDigger/cat/Language/js.txt" \
        "$FFUF_SECLISTS_JS" &
task_pid=$!
spinner $task_pid

log "Reviewing Fuzzing results."
ffuf_seclists_count="$(wc -l $FFUF_SECLISTS_JS | sed -e 's/^[[:space:]]*//' | cut -d " " -f 1)"
log "Results from Fuzzing Known directories with SecLists $ffuf_seclists_count"


# Generate a wordlist of renamed javascript filenames based on a pre-canned 
# wordlist. This will create a file identified by KNOWN_JS_FILES_RENAME
log "Generating basic wordlist from pre-canned modifications."
generate_renamed_js_wordlist "$KNOWN_JS_FILES" &
task_pid=$!
spinner $task_pid

# Using the rename wordlist, fuzz known JS directories for renamed JS based
# on our manual renamed wordlist above. Extract results to a file. 
log "Fuzz known directories for renamed known wordlist JS filenames."
touch "$FFUF_PRECANNED_JS"
fuzz_known_directories "$KNOWN_JS_FILES_RENAME" "$FFUF_PRECANNED_JS" &
task_pid=$!
spinner $task_pid

log "Reviewing Fuzzing results."
ffuf_precanned_count="$(wc -l $FFUF_PRECANNED_JS | sed -e 's/^[[:space:]]*//' | cut -d " " -f 1)"
log "Results from Fuzzing Known directories with precanned wordlist  $ffuf_seclists_count"


# If set, use OpenAI to halicinate on known filenames for altername renames
# of same files. Use that new world list to fuzz across known JS directories.
# The generated names are stored in file identified by KNOWN_JS_FILES_AI_RENAME.
if [ "$brain" = "true" ]; then
    log "Using OpenAI to generate possible file renames. $KNOWN_JS_FILES"
    generate_renamed_js_ai_wordlist $KNOWN_JS_FILES &
    task_pid=$!
    spinner $task_pid
    status=$?

    if [ $status -ne 0 ]; then
        log "Aborting AI processing."
    else
        log "Fuzz known directories for AI generated wordlist."
        touch "$FFUF_AI_JS"
        fuzz_known_directories "$KNOWN_JS_FILES_AI_RENAME" "$FFUF_AI_JS" &
        task_pid=$!
        spinner $task_pid

        log "Reviewing Fuzzing results."
        ffuf_ai_count="$(wc -l $FFUF_AI_JS | sed -e 's/^[[:space:]]*//' | cut -d " " -f 1)"
        log "Results from Fuzzing Known directories with ai wordlist  $ffuf_ai_count"
    fi
fi


# Collect all fuzzed results in a single file.
cat "$FFUF_AI_JS" "$FFUF_PRECANNED_JS" "$FFUF_SECLISTS_JS" > $FFUF_FINAL_RESULTS

# Lets publish some results
log "----------------------------------"
log "Results:"
log "Directories containing JS:"
logfile "$KNOWN_JS_DIRS_SORTED"
log "Linked JS Files:"
logfile "$KNOWN_JS_FILES"
log "Unlinked JS Files:"
logfile "$FFUF_FINAL_RESULTS"


# Exit.
log "JSHunter is exiting"
exit 0
