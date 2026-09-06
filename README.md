# Entity Name Matcher

**🔗 Live demo:** https://biancabcarlson.github.io/Entity-Name-Matcher/

A dependency-free tool that flags when more than one account shares the same (or reused) PII — matching names, emails, phone numbers, or addresses. Built for KYC / case-review work: catching duplicate accounts, synthetic identities, or an account takeover where the attacker opens a second account using the victim's *retired* contact info (an old email or phone number the victim no longer uses).

`entity_name_matcher.py` does the matching:
- `score_names(a, b)` — fuzzy name similarity (nicknames, initials, reordering, transliteration, legal-suffix noise for orgs)
- `find_pii_collisions(accounts)` — scans a list of account records and flags any pair with matching name/email/phone/address, including a current value on one account matching a *retired* value on another (pulled from `activityLog`-style change history)

```
python entity_name_matcher.py "Robert J. Smith" "Bob Smith"
python entity_name_matcher.py --accounts accounts.json
```

Includes a browser-based live demo (`index.html`, linked above) that runs entirely client-side — nothing is saved or uploaded. It comes pre-loaded with this case's two accounts and shows any flagged overlap immediately, no manual search needed; there's also a quick-check field to test an additional name/email/phone/address against the loaded case.

## Used alongside

Paired with the [`simulated-account`](https://github.com/biancabcarlson/simulated-account) fixture, which includes a second account (`account-data-2.json`) that reuses the primary account's retired email and phone at the same address — the case this tool is built to catch.

## Other tools in this series

- [Case Calculator](https://biancabcarlson.github.io/Case-Calculator/)
- [Report Template Filler](https://biancabcarlson.github.io/Report-Template-Filler/)
- [OSINT Tool](https://biancabcarlson.github.io/OSINT-Tool/)
- [Case Doc Tracker](https://biancabcarlson.github.io/Case-Doc-Tracker/)
- [Entity Name Matcher](https://biancabcarlson.github.io/Entity-Name-Matcher/) *(this repo)*
- [Case Timeline Builder](https://biancabcarlson.github.io/Case-Timeline-Builder/)
