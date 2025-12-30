This is a python script made for checking a large amount of hashes inside an enterprise environment.
You must have access to Mandiant Advantage and their API for this tool to be used.
This was extremely useful for checking a large amount of hashes and determining their threat actor associations, malware families and relevent campaigns.

Syntax -
python3 HashHunter.py -f hashes.txt -o hash_output.json

Once the script completes it shows you the following summary output:

<img width="477" height="167" alt="image" src="https://github.com/user-attachments/assets/60920a5f-862c-4755-a084-8f1ff9736310" />

The JSON logs show the following information:

Hash: The hash from the list it searched the Mandiant DB for
found: true/false for if it was found in the Mandiant DB
timestamp: when the hash was searched for
threat_score: a numerical rating (0-100) indicating an indicator's (IP, hash, URL) potential impact
mscore: a dynamic rating (0-100) for digital indicators (IPs, URLs, hashes) that quantifies their threat level
confidence_score: a confidence rating on how malicious an IoC is 0-100
verdict: unknown, benign, suspicious, malicious
malware_families: relevant malware associations to a IoC
threat_actors: the threat actors associated with an IoC
campaigns: associated threat actor/malware campaigns related to an IoC
first_seen: when the IoC was first seen
last_seen: when the IoC was last seen
last_updated: shows when the IoC information was last updated in Mandiant's DB
sources: shows the source of the hash i.e Mandiant, URLhaus


<img width="792" height="681" alt="image" src="https://github.com/user-attachments/assets/5e6fd5ec-fc42-40a8-a60b-2b12432849b1" />
