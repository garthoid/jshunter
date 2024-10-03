# jshunter


```code
   _      _                                  
  (_)    | |                _                
   _  ___| | _  _   _ ____ | |_  ____  ___
  | |/___) || \| | | |  _ \|  _)/ _  )/ ___) 
  | |___ | | | | |_| | | | | |_( (/ /| |     
 _| (___/|_| |_|\____|_| |_|\___)____)_|     
(__/ @garthoid 2024                        
```

## Introduction
A Tool for linux based systems to search for linked and unlinked JavaScript files on a target. It is losely based on [ScriptHunter](https://github.com/robre/scripthunter). 

The goal of JSHunter is to find JavaScript files associated with an URL for reconnaissance purposes using a variety of methods. 

The methods include:

- Using [Gau](https://github.com/lc/gau) to find content from WayBackMachine, CommonCrawl, and AlienVaults's Open Threat Exchange.
- Using [Hawrawler](https://github.com/hakluke/hakrawler) to find live linked content on the target site.
- Using [SecLists](https://github.com/danielmiessler/SecLists) to fuzz for common JavaScript filesnames with fuzzing tools in known directories on the target.
- Using fuzzing tools such as [FFUF](https://github.com/ffuf/ffuf) to find unlinked content based on SecLists and generated worldlists.
- Using AI (yes, I know, sorry) to ~~generate~~ halucinate common backup and rename filenames based on the found linked set of filenames.
- Using [JQ](https://jqlang.github.io/jq/) to parse json output.
- Using [httpx](https://github.com/projectdiscovery/httpx) to confirm endpoints.

The high level approach to this tool is as follows:

1. Find linked JavaScript files live on the target.
2. Find current and historical linked content.
3. Find dormant unlinked JavaScript files based on SecList wordlists.
4. Find dormant unlinked JavaScript files from AI halucinating wordlists based on known linked files. 


The directory names and filenames of linked live files on the target are then used as a basis to generate potential renamed files. If configured, we get OpenAI to halucinate an additional renamed wordlist.

## Example Usage
```code
./jshunter.sh -t https://ginandjuice.shop -d /usr/share/seclists -a
```

## Installation
1. Install Dependencies. Ensure they can be found on the system PATH.
2. Clone this repo.
3. Change directory to cloned repository directory.
4. Run.

## Sample Run
```code
$ ./jshunter.sh -t https://ginandjuice.shop -d /usr/share/seclists -a 
   _      _                                  
  (_)    | |                _                
   _  ___| | _  _   _ ____ | |_  ____  ___  _
  | |/___) || \| | | |  _ \|  _)/ _  )/ ___) 
  | |___ | | | | |_| | | | | |_( (/ /| |     
 _| (___/|_| |_|\____|_| |_|\___)____)_|     
(__/ @garthoid 2024                        
                                             
[*] Silent mode turned off
[*] SecLists Root testing
[*] SecLists Root directory set to /usr/share/seclists
[*] SecLists Root directory valid
[*] AI mode Turned on
[*] OPENAI_API_KEY is set
[*] target is https://ginandjuice.shop
[*] domain is ginandjuice.shop
[*] Checking if https://ginandjuice.shop is responsive
[*] https://ginandjuice.shop is reachable
[*] Working directory is /tmp/jshunter/ginandjuice.shop
[*] Running GAU
[*] Gau found 7 scripts
[*] Running hakrawler
[*] HAKRAWLER found 9 scripts!
[*] JSHunter has found 2 directories containing linked JS content.
[*] Creating output file for SecList fuzzing: /tmp/jshunter/ginandjuice.shop/ffuf-seclist-js.txt
[*] Running FFUF on https://ginandjuice.shop/resources/footer/js with /usr/share/seclists/Discovery/Web-Content/SVNDigger/cat/Language/js.txt
[|]  [*] Running FFUF on https://ginandjuice.shop/resources/js with /usr/share/seclists/Discovery/Web-Content/SVNDigger/cat/Language/js.txt
[*] Reviewing Fuzzing results.
[*] Results from Fuzzing Known directories with SecLists 0
[*] Generating basic wordlist from pre-canned modifications.
[*] Fuzz known directories for renamed known wordlist JS filenames.
[*] Running FFUF on https://ginandjuice.shop/resources/footer/js with /tmp/jshunter/ginandjuice.shop/known-js-files-renamed.txt
[/]  [*] Running FFUF on https://ginandjuice.shop/resources/js with /tmp/jshunter/ginandjuice.shop/known-js-files-renamed.txt
[*] Reviewing Fuzzing results.
[*] Results from Fuzzing Known directories with precanned wordlist  0
[*] Using OpenAI to generate possible file renames. /tmp/jshunter/ginandjuice.shop/known-js-files.txt
[*] ai names source: /tmp/jshunter/ginandjuice.shop/known-js-files.txt
[\]  [*] AI found 807 potential names.
[*] Fuzz known directories for AI generated wordlist.
[*] Running FFUF on https://ginandjuice.shop/resources/footer/js with /tmp/jshunter/ginandjuice.shop/known-js-files-ai-renamed.txt
[\]  [*] Running FFUF on https://ginandjuice.shop/resources/js with /tmp/jshunter/ginandjuice.shop/known-js-files-ai-renamed.txt
[*] Reviewing Fuzzing results.
[*] Results from Fuzzing Known directories with ai wordlist  0
[*] ----------------------------------
[*] Results:
[*] Directories containing JS:
https://ginandjuice.shop/resources/footer/js
https://ginandjuice.shop/resources/js
[*] Linked JS Files:
angular_1-7-7.js
deparam.js
react.development.js
react-dom.development.js
scanme.js
searchLogger.js
subscribeNow.js
angular_1-7-7.js
deparam.js
react.development.js
react-dom.development.js
scanme.js
searchLogger.js
stockCheck.js
subscribeNow.js
xmlStockCheckPayload.js
[*] Unlinked JS Files:
[*] JSHunter is exiting
```

## Forward Thinking
- Add other AIs.
- Add other wordlist sources or user provided wordlists.
- Improve the halucination prompt.
- Tidy temporary files upon exit.
- Option for results in user provided file.
