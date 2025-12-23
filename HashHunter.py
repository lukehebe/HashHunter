#Name: HashHunter-v1.0
#Description: This is a tool to verify the legitimacy of hashes inside enterprise enviornments. 
#It utilizes the mandiant Advantage API and ingests file hashes (MD5, SHA256, SHA1) from a given text file.
#The script contains 2 required arguments one for the ingestion of hashes to verify and one for an output file that will be saved in JSON format.
#After the arguments are set and the script starts it will begin looping through the indicator API endpoint.
#The saved results include - hash, found(True), Timestamp, threat score, mscore, confidence score, verdict, malware familes, threat actors, campaigns, first_seen, last_seen, last_updated, sources
#Author: lukehebe


import requests
import argparse
import json
import base64
import time
from datetime import datetime
import hashlib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_args(): #This is the first argument for ingesting the file hashes.
    parser = argparse.ArgumentParser(description="Mandiant Advantage Hash Hunter :)")
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="File containing SHA256 hashes (one per line)"
    )
    parser.add_argument( #This is the second argument it is not required but implemented for better control.
        "--delay", type=float, default=1.0,
        help="Delay between requests speed up or slow down based on needs (API allows 1 request per second)"
    )
    parser.add_argument( #Argument for saving to an output file.
        "-o", "--output",
        required=True,
        help="This is the name of the output file you want to save the results to in JSON format"
    )
    return parser.parse_args()

def get_auth_token(): # Put your own mandiant api key inside here:
    """API Authentication using Basic Auth to get the Bearer Token"""
    api_key = 'YOUR API KEY HERE'
    api_secret = 'YOUR SECRET KEY HERE'

    #This is for creating our basic authentication header 
    credentials = f"{api_key}:{api_secret}"
    encoded_creds = base64.b64encode(credentials.encode()).decode()
    token_url = 'https://api.intelligence.mandiant.com/token'
    headers = {
        'Authorization': f'Basic {encoded_creds}', #This is our web request headers
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'X-App-Name': 'hash-hunter-v1.0'
    }
    data = {
        'grant_type': 'client_credentials'
    }
 
    try: #This will make a post request to the token endpoint to obtain our Bearer token
        response = requests.post(token_url, headers=headers, data=data, timeout=30, verify=False)
        response.raise_for_status()
        token_data = response.json() #parses JSON response containing access_token and expires_in
        expires_hours = token_data.get('expires_in', 0) / 3600 #Tells how long the token is active for
        print(f"[$$$] API Authentication Successful")
        print(f"[$$$] Bearer token valid for {expires_hours:.1f} hours") 
        return token_data.get('access_token')
        
    except requests.exceptions.RequestException as e:  #This is the response if the authentication fails for whatever reason. Displays status code for troubleshooting
        print(f"[!!!] Authentication Failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"     Status Code: {e.response.status_code}")
            print(f"     Response: {e.response.text}")
        return None

#This is our first function after we have authentication it determines what hashes are what from our list based on the length
def detect_hash_type(hash_value):
    """Detect hash type based on length"""
    hash_len = len(hash_value)
    if hash_len == 32:
        return "md5"
    elif hash_len == 40:
        return "sha1"
    elif hash_len == 64:
        return "sha256"
    else:
        return None

#this function establishes our authentication in order to make requests to the indicator endpoint
def search_hash(hash_value, auth_token, retry_count=0):
    """Verify hash integrity from our list"""
    indicator_url = "https://api.intelligence.mandiant.com/v4/indicator"

    hash_type = detect_hash_type(hash_value)
    if not hash_type:
        print(f"      Invalid hash length: {len(hash_value)} characters")
        return {"hash": hash_value, "error": "invalid_hash_format"}

    headers = {
        'Authorization': f'Bearer {auth_token}', # Uses our token we obtained on line 53 to authenticate to the endpoint and check our hashes.
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-App-Name': 'hash-hunter-v1.0'
    }

    payload = { # API structure with hash type filter
        "requests": [{
            "values": [hash_value],
            "hash_type": hash_type 
        }]
    }

    try: #Sends a post request running our hashes
        response = requests.post(indicator_url, json=payload, headers=headers, timeout=30, verify=False)

        #This is for the rate limiting it will back off if it exceeds
        if response.status_code == 429:
            if retry_count < 3:
                wait_time = 2 ** retry_count * 60 #This will create a wait time if rate limit is exceeded and display how long i.e 60s, 120s, 240s
                print(f"[!] Rate limit hit. Gotta wait {wait_time}s...")
                time.sleep(wait_time)
                return search_hash(hash_value, auth_token, retry_count + 1)
            else:
                print(f"[-] Max retries exceeded for {hash_value}")
                return {"hash": hash_value, "error": "rate_limit_exceeded"}
        
        #This is for when a token expires
        if response.status_code == 401:
            print(f"[!!!] Bearer token expired - restart script")
            return {"hash": hash_value, "error": "token_expired"}
        
        #This is when a hash isnt found in the database
        if response.status_code == 204:
            return {
                "hash": hash_value,
                "hash_type": hash_type,
                "found": False,
                "verdict": "UNKNOWN",
                "threat_score": 0,
                "mscore": 0
            }
        
        #This for a successful response
        if response.status_code == 200:
            result = parse_v4_response(hash_value, response.json())
            result["hash_type"] = hash_type  # Add hash type to result
            return result
        
        response.raise_for_status() #This is for other errors
    except requests.exceptions.RequestException as e:
            print(f"[-] Error searching {hash_value}: {e}")
            return {"hash": hash_value, "error": str(e)}

#This is a function for our response this is where the magic happens -
def parse_v4_response(hash_value, response_data):
    """Parse Indicator Response"""
    result = { #These are the mandiant API provided response details
        "hash": hash_value,
        "found": True,
        "timestamp": datetime.now().isoformat(),
        "threat_score": 0,
        "mscore": 0,
        "confidence_score": 0,
        "verdict": "UNKNOWN",
        "malware_families": [],
        "threat_actors": [],
        "campaigns": [],
        "first_seen": None,
        "last_seen": None,
        "last_updated": None,
        "sources": []
    }

    # Now we need to extract the indicator data from the response
    indicators = response_data.get("indicators", [])
    if not indicators:
        result["found"] = False
        return result
    
    for indicator in indicators:
        #These are the threat scores
        if indicator.get("mscore"):
            result["mscore"] = max(result["mscore"], indicator["mscore"])
        if indicator.get("threat_score"):
            result["threat_score"] = max(result["threat_score"], indicator["threat_score"])
        
        #verdict:
        if indicator.get("verdict"):
            result["verdict"] = indicator["verdict"]
        
        #Malware associations
        if indicator.get("malware"):
            for malware in indicator["malware"]:
                result["malware_families"].append({
                    "name": malware.get("name"),
                    "id": malware.get("id")
                })
        #Threat actor associations
        if indicator.get("attributed_associations"):
            for assoc in indicator["attributed_associations"]:
                if assoc.get("type") == "threat-actor":
                    result["threat_actors"].append({
                        "name": assoc.get("name"),
                        "id": assoc.get("id")
                    })

        #Campaign associations
        if indicator.get("campaigns"):
            for campaign in indicator["campaigns"]:
                result["campaigns"].append({
                    "name": campaign.get("name"),
                    "id": campaign.get("id")
                })
        #temporal data
        result["first_seen"] = indicator.get("first_seen")
        result["last_seen"] = indicator.get("last_seen")
        result["last_updated"] = indicator.get("last_updated")

        #sources
        if indicator.get("sources"):
            result["sources"] = indicator["sources"]
    return result

#summary of findings function - 

def print_summary(result):
    """Print formatted summary of hash check"""
    hash_val = result["hash"]

    if result.get("error"):
        print(f"      ERROR: {result['error']}")
        return
    
    if not result.get("found"):
        print(f"       No Threat Intelligence Available")

    verdict = result.get("verdict", "UNKNOWN")
    mscore = result.get("mscore", 0)
    threat_score = result.get("threat_score", 0)

    #Severity calculator -  These may need to be adjusted. All indicators returned suspicious or malicious should be checked against other sources

    if verdict in ["malicious", "MALICIOUS"] or mscore >= 80 or threat_score >= 80:
        severity = "MALICIOUS"
    elif verdict in ["suspicious", "SUSPICIOUS"] or mscore >= 50 or threat_score >= 50:
        severity = "SUSPICIOUS"
    else:
        severity = "BENIGN/LOW"
    print(f"     {severity} | MScore: {mscore} | ThreatScore: {threat_score}")

    #this is the output of associations (malware, threat actor, campaigns).
    if result.get("malware_families"):
        malware_names = [m["name"] for m in result["malware_families"]]
        print(f"       └─ Malware: {', '.join(malware_names)}")

    if result.get("threat_actors"):
        actor_names = [a["name"] for a in result["threat_actors"]]
        print(f"       └─ Actors: {', '.join(actor_names)}")

    if result.get("campaigns"):
        campaign_names = [c["name"] for c in result["campaigns"]]
        print(f"       └─ Campaigns: {', '.join(campaign_names)}")

# Get command line argus (file path, delay (optional), output file) This is our ioc checking process ^^ Above is our backbone 
def main():
    args = parse_args()

    print("=" * 70)
    print("        Cyber Threat Hunt - HashHunt - Happy Hunting!")
    print("=" * 70)
    print(f"[**] Rate Limit Delay: {args.delay}s between requests\n")

    # Get bearer token 
    auth_token = get_auth_token() #This calls the function we defined earlier
    if not auth_token: #If auth fails it exits and try again maybe check api key and secret key if it fails
        print("[--] Authentication has failed. Exiting.")
        return
    print()

    #This is where our hashes are loaded from the file
    try:
        with open(args.file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
        print(f"[$$] Loaded {len(hashes)} hashes from {args.file}\n")
    except FileNotFoundError:
        print(f"[--] File not found: {args.file}")
        return

    #now process each hash
    results = []  #Initialize results list
    stats = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0, "errors": 0}

    for idx, hash_value in enumerate(hashes, 1):
            print(f"[{idx}/{len(hashes)}] {hash_value[:24]}...")
            result = search_hash(hash_value, auth_token)
            results.append(result)

            # Print the summary
            print_summary(result)

            #update the statistics
            if result.get("error"):
                stats["errors"] += 1
            elif not result.get("found"):
                stats["unknown"] += 1
            else:
                mscore = result.get("mscore", 0)
                if mscore >= 80:
                    stats["malicious"] += 1
                elif mscore >= 50:
                    stats["suspicious"] += 1
                else:
                    stats["benign"] += 1
            # Rate limit delay
            if idx < len(hashes):
                time.sleep(args.delay)
            print()

        # save results to JSON
    with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)

        # Final summary --------
    print("=" * 70)
    print("                         SUMMARY")
    print("=" * 70)
    print(f"Total Hashes:     {len(hashes)}")
    print(f"Malicious:     {stats['malicious']}")
    print(f"Suspicious:    {stats['suspicious']}")
    print(f"Benign:        {stats['benign']}")
    print(f"Unknown:       {stats['unknown']}")
    print(f"Errors:        {stats['errors']}")
    print(f"\n[+] Results saved to: {args.output}")
    print("=" * 70)
if __name__ == "__main__":
    main()
