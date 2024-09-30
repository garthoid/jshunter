# jshunter
A Tool to search for linked and unlinked JavaScript files on a target. It is losely based on [ScriptHunter](https://github.com/robre/scripthunter). 

The goal of JSHunter is to find JavaScript files associated with an URL for reconnaissance purposes using a variety of methods. Methods include:

- Using [Gau](https://github.com/lc/gau) to find content from WayBackMachine, CommonCrawl, and AlienVaults's Open Threat Exchange.
- Using [Hawrawler](https://github.com/hakluke/hakrawler) to find live linked content on the target site.
- Using [SecLists](https://github.com/danielmiessler/SecLists) to fuzz for common JavaScript filesnames with fuzzing tools in known directories on the target.
- Using fuzzing tools such as [FFUF](https://github.com/ffuf/ffuf) to find unlinked content based on SecLists and generated worldlists.
- Using AI (yes, I know, sorry) to -generate- halucinate common backup and rename filenames based on the found linked set of filenames.
- Using JQ to parse json output.

Based on these methods, JSHunter requires other tools as pre-requists. These include:

- Gau
- Hakrawler
- SecLists
- FFUF
- JQ 

The high level approach to this tool is as follows:

1. Find linked JavaScript files live on the target.
2. Find current and historical linked content.
3. Find dormant renamed content.
4. Find JavaScript content based on Wordlists.

The directory names and filenames of linked live files on the target are then used as a basis to generate potential renamed files. If configured, we get OpenAI to halucinate an additional renamed wordlist.
