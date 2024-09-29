# jshunter
A Tool to search for linked and unlinked JavaScript files on a target. It is losely based on [ScriptHunter](https://github.com/robre/scripthunter). 

The goal of JSHunter is to find JavaScript files associated with an URL for reconnaissance purposes using a variety of methods. Methods include:

- Using Gau to find content from WayBackMachine, CommonCrawl, and AlienVaults's Open Threat Exchange.
- Using hawrawler to find live linked content on the target site.
- Using SecLists to fuzz for common JavaScript filesnames with fuzzing tools.
- Using fuzzing tools such as FFUF to find unlinked content based on SecLists and generated worldlists.
- Using AI (yes, I know, sorry) to generate common backup and rename filenames based on the found linked set of filenames.

Based on these methods, JSHunter requires other tools as pre-requists.
