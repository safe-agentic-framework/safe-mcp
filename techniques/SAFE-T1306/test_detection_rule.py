import json

def match_super_token(log):
    return (
        log.get("event.action") == "token.issued" and
        any(scope in log.get("token.scope", "") for scope in ["admin", "*:*", "system.*", "root"]) and
        log.get("token.cnf.jkt") in [None, "", "undefined"]
    )

def match_missing_pop(log):
    return (
        log.get("event.action") == "token.validated" and
        log.get("token.cnf.jkt") in [None, "", "undefined"] and
        log.get("config.pop_required") == True
    )

def match_unknown_kid(log):
    return (
        log.get("event.action") == "token.signature.valid" and
        log.get("token.kid") == "unknown-key-999"
    )

def match_discovery_poisoning(log):
    return (
        log.get("event.action") in ["discovery.fetch", "openid.configuration", "jwks.fetch"] and
        log.get("issuer.url") == "https://malicious-discovery.example"
    )

def run_tests(logs):
    matches = []
    for log in logs:
        if match_super_token(log):
            matches.append(("Super-Token", log))
        elif match_missing_pop(log):
            matches.append(("Missing PoP", log))
        elif match_unknown_kid(log):
            matches.append(("Unknown KID", log))
        elif match_discovery_poisoning(log):
            matches.append(("Discovery Poisoning", log))
    return matches

if __name__ == "__main__":
    with open("test-logs.json") as f:
        logs = json.load(f)
    results = run_tests(logs)
    print(f"Detected {len(results)} matching log(s):")
    for label, match in results:
        print(f"\nMatch: {label}")
        print(json.dumps(match, indent=2))
