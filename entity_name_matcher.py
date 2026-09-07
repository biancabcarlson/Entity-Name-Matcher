#!/usr/bin/env python3
"""
Entity Name Matcher
====================

A dependency-free tool for KYC / case-review work that flags when more
than one account shares the same (or reused) PII -- name variants,
matching emails, matching phone numbers, matching addresses -- a common
signal for duplicate accounts, synthetic identities, or an account
takeover where the attacker recycles the victim's retired contact info
on a second account.

No network calls, no third-party packages -- stdlib only, so it runs
anywhere Python 3 does.

Usage
-----
Compare two names directly (fuzzy name score only):

    python entity_name_matcher.py "Robert J. Smith" "Bob Smith"

Scan a set of account records for PII collisions -- this is the main
use case. Give it a JSON file containing a list of account objects,
each with at least a "name" field and any of "email" / "phone" /
"address":

    python entity_name_matcher.py --accounts accounts.json

Show the score breakdown instead of just the final number:

    python entity_name_matcher.py "Bob Smith" "Robert Smith" --explain

Treat names as organizations (adds legal-suffix stripping: Inc, LLC, Ltd...):

    python entity_name_matcher.py "Acme Trading Co." "ACME TRADING, LLC" --org

As a library:

    from entity_name_matcher import score_names, find_pii_collisions
    result = score_names("Bob Smith", "Robert Smith")
    print(result.score, result.verdict)

    collisions = find_pii_collisions(accounts)
    for c in collisions:
        print(c.account_a["name"], "<->", c.account_b["name"], c.reasons)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Common English given-name nicknames/diminutives, normalized to a canonical
# form. Not exhaustive -- extend freely for your own case set.
NICKNAMES: dict[str, str] = {
    "bob": "robert", "bobby": "robert", "rob": "robert", "robbie": "robert",
    "bill": "william", "billy": "william", "will": "william", "willy": "william", "liam": "william",
    "dick": "richard", "rich": "richard", "richie": "richard", "rick": "richard", "ricky": "richard",
    "jim": "james", "jimmy": "james", "jamie": "james",
    "jack": "john", "johnny": "john", "jon": "john", "jonny": "john",
    "mike": "michael", "mikey": "michael", "mick": "michael", "micky": "michael",
    "dave": "david", "davey": "david",
    "matt": "matthew", "matty": "matthew",
    "chris": "christopher", "topher": "christopher",
    "nick": "nicholas", "nicky": "nicholas", "nico": "nicholas",
    "andy": "andrew", "drew": "andrew",
    "tony": "anthony", "ant": "anthony",
    "steve": "steven", "stevie": "steven",
    "joe": "joseph", "joey": "joseph",
    "sam": "samuel", "sammy": "samuel",
    "ben": "benjamin", "benny": "benjamin",
    "alex": "alexander", "al": "alexander",
    "ed": "edward", "eddie": "edward", "ted": "edward", "teddy": "edward", "ned": "edward",
    "greg": "gregory",
    "ken": "kenneth", "kenny": "kenneth",
    "larry": "lawrence", "laurie": "lawrence",
    "pat": "patrick", "paddy": "patrick",
    "tom": "thomas", "tommy": "thomas",
    "dan": "daniel", "danny": "daniel",
    "frank": "francis", "frankie": "francis",
    "gerry": "gerald", "jerry": "gerald",
    "hank": "henry", "harry": "henry",
    "peggy": "margaret", "meg": "margaret", "maggie": "margaret", "marge": "margaret", "greta": "margaret",
    "liz": "elizabeth", "beth": "elizabeth", "betty": "elizabeth", "eliza": "elizabeth", "libby": "elizabeth", "lisa": "elizabeth",
    "kate": "katherine", "katie": "katherine", "kathy": "katherine", "kit": "katherine", "cathy": "catherine",
    "sue": "susan", "susie": "susan", "suzy": "susan",
    "jen": "jennifer", "jenny": "jennifer",
    "cindy": "cynthia",
    "deb": "deborah", "debbie": "deborah",
    "barb": "barbara", "barbie": "barbara",
    "peg": "margaret",
    "pam": "pamela",
    "vicky": "victoria", "vic": "victoria",
    "trish": "patricia", "patty": "patricia", "tricia": "patricia",
    "sandy": "sandra",
    "cathy2": "catherine",
    "abby": "abigail",
    "ginny": "virginia", "ginger": "virginia",
    "peggy2": "margaret",
    "connie": "constance",
    "franny": "frances", "fanny": "frances",
    "gina": "regina",
    "nancy": "ann",
    "annie": "ann", "nan": "ann",
    "ronnie": "ronald", "ron": "ronald",
    "wally": "walter", "walt": "walter",
    "phil": "philip",
    "vince": "vincent",
    "les": "leslie",
    "janet": "jane", "jan": "jane", "jani": "jane",
}

# Legal-entity suffixes to strip when matching organizations. Order matters
# (longest/most specific first) since stripping is done via longest-suffix
# match after tokenization.
ORG_SUFFIXES = {
    "inc", "incorporated", "llc", "l.l.c", "ltd", "limited", "co", "company",
    "corp", "corporation", "plc", "llp", "lp", "gmbh", "ag", "sa", "srl",
    "bv", "nv", "oy", "kk", "pte", "pty", "sdn", "bhd", "holdings", "group",
    "trust", "foundation", "partners", "associates",
}

# Suffixes that indicate a generational marker on a personal name -- these
# should NOT count against a match (e.g. "John Smith Jr." vs "John Smith").
GENERATIONAL_SUFFIXES = {"jr", "sr", "ii", "iii", "iv", "v"}


@dataclass
class MatchResult:
    name_a: str
    name_b: str
    score: float
    verdict: str
    components: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class PIICollision:
    account_a: dict
    account_b: dict
    name_score: float
    name_verdict: str
    field_matches: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.field_matches) or self.name_score >= 70


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def strip_accents(text: str) -> str:
    """Fold transliteration/diacritic variants to plain ASCII where possible
    (e.g. 'Jose' vs 'José', 'Muller' vs 'Müller')."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def tokenize(name: str, *, is_org: bool = False) -> list[str]:
    """Lowercase, strip accents/punctuation, split into tokens, and drop
    noise tokens (legal suffixes for orgs, generational suffixes for
    people)."""
    folded = strip_accents(name).lower()
    cleaned = []
    for ch in folded:
        cleaned.append(ch if (ch.isalnum() or ch.isspace()) else " ")
    tokens = "".join(cleaned).split()

    noise = ORG_SUFFIXES if is_org else GENERATIONAL_SUFFIXES
    tokens = [t for t in tokens if t not in noise]
    return tokens


def canonicalize_token(token: str) -> str:
    """Expand a nickname to its canonical form, if known."""
    return NICKNAMES.get(token, token)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_phone(phone: str) -> str:
    """Digits only, and drop a leading country code '1' on 11-digit US
    numbers so '(415) 555-0148' and '+1 415-555-0148' match."""
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return digits


def normalize_address(address: str) -> str:
    folded = strip_accents(address or "").lower()
    folded = re.sub(r"[^\w\s]", " ", folded)
    folded = re.sub(r"\s+", " ", folded).strip()
    return folded


# ---------------------------------------------------------------------------
# Scoring components
# ---------------------------------------------------------------------------

def _ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def token_sort_score(tokens_a: list[str], tokens_b: list[str]) -> float:
    """Order-independent string similarity: sort tokens, rejoin, compare.
    Catches 'Smith Robert' vs 'Robert Smith'."""
    a = " ".join(sorted(tokens_a))
    b = " ".join(sorted(tokens_b))
    return _ratio(a, b) * 100


def token_set_score(tokens_a: list[str], tokens_b: list[str]) -> float:
    """Jaccard-style overlap on canonicalized token sets. Catches dropped
    middle names / extra tokens without punishing them too harshly."""
    set_a = {canonicalize_token(t) for t in tokens_a}
    set_b = {canonicalize_token(t) for t in tokens_b}
    if not set_a or not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return (len(intersection) / len(union)) * 100


def best_pairwise_score(tokens_a: list[str], tokens_b: list[str]) -> float:
    """Greedily pair each token in the shorter name with its best match in
    the longer name (canonicalizing nicknames, treating a single initial as
    matching any token with the same first letter), then average.

    This is the component that makes 'R. J. Smith' score highly against
    'Robert James Smith', and 'Bob Smith' score highly against
    'Robert Smith'.
    """
    if not tokens_a or not tokens_b:
        return 0.0

    short, long_ = (tokens_a, tokens_b) if len(tokens_a) <= len(tokens_b) else (tokens_b, tokens_a)
    remaining = list(long_)
    pair_scores = []

    for tok in short:
        canon_tok = canonicalize_token(tok)
        best_score = 0.0
        best_idx = None
        for idx, cand in enumerate(remaining):
            canon_cand = canonicalize_token(cand)

            if len(tok) == 1 or len(cand) == 1:
                # initial vs full token: match on first letter, using the
                # canonicalized form so an initial matches the nickname's
                # formal name too (e.g. "R." should match "Bob" via "Robert")
                s = 100.0 if canon_tok[0] == canon_cand[0] else 0.0
            elif canon_tok == canon_cand:
                s = 100.0
            else:
                s = _ratio(canon_tok, canon_cand) * 100

            if s > best_score:
                best_score = s
                best_idx = idx

        pair_scores.append(best_score)
        if best_idx is not None and best_score > 0:
            remaining.pop(best_idx)

    return sum(pair_scores) / len(pair_scores)


# ---------------------------------------------------------------------------
# Public API -- name scoring
# ---------------------------------------------------------------------------

WEIGHTS = {
    "token_sort": 0.30,
    "token_set": 0.25,
    "pairwise": 0.45,
}

THRESHOLDS = [
    (85, "match"),
    (70, "likely match"),
    (50, "possible match"),
    (0, "no match"),
]


def verdict_for(score: float) -> str:
    for cutoff, label in THRESHOLDS:
        if score >= cutoff:
            return label
    return "no match"


def score_names(name_a: str, name_b: str, *, is_org: bool = False) -> MatchResult:
    tokens_a = tokenize(name_a, is_org=is_org)
    tokens_b = tokenize(name_b, is_org=is_org)

    components = {
        "token_sort": token_sort_score(tokens_a, tokens_b),
        "token_set": token_set_score(tokens_a, tokens_b),
        "pairwise": best_pairwise_score(tokens_a, tokens_b),
    }

    final = sum(components[k] * WEIGHTS[k] for k in WEIGHTS)
    final = round(min(final, 100.0), 1)

    notes = []
    if not tokens_a or not tokens_b:
        notes.append("one or both names produced no usable tokens after cleanup")
    if len(tokens_a) != len(tokens_b):
        notes.append("token count differs -- check for a dropped middle name/initial or extra qualifier")

    return MatchResult(
        name_a=name_a,
        name_b=name_b,
        score=final,
        verdict=verdict_for(final),
        components={k: round(v, 1) for k, v in components.items()},
        notes=notes,
    )


def rank_candidates(query: str, candidates: list[str], *, is_org: bool = False) -> list[MatchResult]:
    results = [score_names(query, cand, is_org=is_org) for cand in candidates]
    results.sort(key=lambda r: r.score, reverse=True)
    return results


# ---------------------------------------------------------------------------
# Public API -- cross-account PII collision detection
# ---------------------------------------------------------------------------

PII_FIELDS = {
    "email": normalize_email,
    "phone": normalize_phone,
    "address": normalize_address,
}


def compare_accounts(account_a: dict, account_b: dict, *, is_org: bool = False) -> PIICollision:
    """Compare two account records (dicts with a 'name' field, current PII
    in 'email' / 'phone' / 'address', and optionally 'priorEmails' /
    'priorPhones' lists of retired values) and report the name-similarity
    score plus any PII overlap -- including one account's current contact
    info matching the *other* account's retired contact info, which is how
    an attacker re-using a victim's old email/phone on a second account
    shows up."""
    name_a = account_a.get("name", "")
    name_b = account_b.get("name", "")
    name_result = score_names(name_a, name_b, is_org=is_org)

    field_matches = []
    reasons = []

    for field_name, normalize in PII_FIELDS.items():
        val_a = account_a.get(field_name)
        val_b = account_b.get(field_name)
        if val_a and val_b and normalize(val_a) == normalize(val_b):
            field_matches.append(field_name)
            reasons.append(f"same {field_name} ({val_a})")

    for field_name, prior_key in (("email", "priorEmails"), ("phone", "priorPhones")):
        normalize = PII_FIELDS[field_name]
        val_a, val_b = account_a.get(field_name), account_b.get(field_name)
        prior_a = [normalize(x) for x in account_a.get(prior_key, [])]
        prior_b = [normalize(x) for x in account_b.get(prior_key, [])]

        if val_b and normalize(val_b) in prior_a:
            field_matches.append(f"{field_name} (retired)")
            reasons.append(
                f"{name_b}'s {field_name} matches {name_a}'s retired {field_name} ({val_b})"
            )
        if val_a and normalize(val_a) in prior_b:
            field_matches.append(f"{field_name} (retired)")
            reasons.append(
                f"{name_a}'s {field_name} matches {name_b}'s retired {field_name} ({val_a})"
            )

    if name_result.score >= 70:
        reasons.append(f"name {name_result.verdict} ({name_result.score}/100)")

    return PIICollision(
        account_a=account_a,
        account_b=account_b,
        name_score=name_result.score,
        name_verdict=name_result.verdict,
        field_matches=field_matches,
        reasons=reasons,
    )


def find_pii_collisions(accounts: list[dict], *, is_org: bool = False) -> list[PIICollision]:
    """Compare every pair of accounts and return the ones worth flagging --
    any exact PII field overlap (email/phone/address), or a name score of
    70+ ('likely match' or better)."""
    flagged = []
    for i in range(len(accounts)):
        for j in range(i + 1, len(accounts)):
            collision = compare_accounts(accounts[i], accounts[j], is_org=is_org)
            if collision.flagged:
                flagged.append(collision)
    return flagged


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def load_name_list(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"no such file: {path}")

    if p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames and "name" in reader.fieldnames:
                return [row["name"].strip() for row in reader if row.get("name", "").strip()]
            # no "name" column -- fall back to first column of every row
            f.seek(0)
            reader2 = csv.reader(f)
            rows = list(reader2)
            return [r[0].strip() for r in rows if r and r[0].strip()]

    with p.open(encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def load_accounts(path: str) -> list[dict]:
    """Load a JSON file containing a list of account records (dicts with at
    least a 'name' field). Also accepts a simulated-account style fixture
    (an object with 'profile' and optional 'relatedAccounts'), which is
    flattened into the same list-of-records shape, pulling retired
    email/phone values out of 'activityLog' along the way."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"no such file: {path}")

    with p.open(encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict) and "profile" in data:
        accounts = [_flatten_account(data)]
        for related in data.get("relatedAccounts", []):
            accounts.append(_flatten_account(related))
        return accounts

    raise ValueError(
        "expected a JSON list of account records, or a fixture object with "
        "a 'profile' key (optionally with 'relatedAccounts')"
    )


def _extract_contact_history(account: dict) -> dict:
    """Pull retired email/phone values out of an account's activityLog,
    where entries look like {"event": "email_changed", "detail": "old -> new"}."""
    prior_emails, prior_phones = [], []
    for entry in account.get("activityLog", []):
        event = entry.get("event", "")
        detail = entry.get("detail", "")
        parts = re.split(r"->|\u2192", detail)  # "->" or "→"
        if len(parts) != 2:
            continue
        old_value = parts[0].strip()
        if event == "email_changed" and old_value:
            prior_emails.append(old_value)
        elif event == "phone_updated" and old_value:
            prior_phones.append(old_value)
    return {"priorEmails": prior_emails, "priorPhones": prior_phones}


def _flatten_account(account: dict) -> dict:
    profile = account.get("profile", account)
    record = {
        "name": profile.get("name"),
        "email": profile.get("email"),
        "phone": profile.get("phone"),
        "address": profile.get("address"),
        "accountNumberMasked": profile.get("accountNumberMasked"),
    }
    record.update(_extract_contact_history(account))
    return record


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_result(result: MatchResult, *, explain: bool) -> None:
    print(f"{result.name_a!r} vs {result.name_b!r}")
    print(f"  score:   {result.score}/100  ({result.verdict})")
    if explain:
        for k, v in result.components.items():
            print(f"    {k:>11}: {v}")
        for note in result.notes:
            print(f"    note: {note}")


def print_collision(collision: PIICollision) -> None:
    a = collision.account_a.get("name", "?")
    b = collision.account_b.get("name", "?")
    print(f"{a!r} <-> {b!r}")
    print(f"  name score: {collision.name_score}/100 ({collision.name_verdict})")
    if collision.field_matches:
        print(f"  shared PII: {', '.join(collision.field_matches)}")
    for reason in collision.reasons:
        print(f"    - {reason}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fuzzy-match entity/person names and flag cross-account PII reuse for KYC and case-review work.",
    )
    parser.add_argument("name_a", nargs="?", help="first name to compare")
    parser.add_argument("name_b", nargs="?", help="second name to compare")
    parser.add_argument("--query", help="a single name to compare against --list")
    parser.add_argument("--list", dest="list_path", help="path to a .txt (one name/line) or .csv (with a 'name' column) file of candidate names")
    parser.add_argument("--accounts", dest="accounts_path", help="path to a JSON file of account records (or a simulated-account fixture) to scan for PII collisions across accounts")
    parser.add_argument("--top", type=int, default=10, help="max candidates to show when using --list (default 10)")
    parser.add_argument("--threshold", type=float, default=0.0, help="only show results at or above this score when using --list")
    parser.add_argument("--org", action="store_true", help="treat names as organizations (strips legal suffixes like Inc/LLC/Ltd)")
    parser.add_argument("--explain", action="store_true", help="show the score breakdown, not just the final number")
    parser.add_argument("--csv", dest="as_csv", action="store_true", help="print results as CSV (name,score,verdict)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.accounts_path:
        try:
            accounts = load_accounts(args.accounts_path)
        except (FileNotFoundError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

        collisions = find_pii_collisions(accounts, is_org=args.org)

        if args.as_csv:
            writer = csv.writer(sys.stdout)
            writer.writerow(["account_a", "account_b", "name_score", "name_verdict", "shared_pii_fields"])
            for c in collisions:
                writer.writerow([
                    c.account_a.get("name", ""),
                    c.account_b.get("name", ""),
                    c.name_score,
                    c.name_verdict,
                    "|".join(c.field_matches),
                ])
        else:
            print(f"{len(accounts)} accounts scanned, {len(collisions)} flagged pair(s)")
            print()
            for c in collisions:
                print_collision(c)
                print()
        return 0

    if args.query and args.list_path:
        try:
            candidates = load_name_list(args.list_path)
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

        results = rank_candidates(args.query, candidates, is_org=args.org)
        results = [r for r in results if r.score >= args.threshold][: args.top]

        if args.as_csv:
            writer = csv.writer(sys.stdout)
            writer.writerow(["name", "score", "verdict"])
            for r in results:
                writer.writerow([r.name_b, r.score, r.verdict])
        else:
            print(f"query: {args.query!r}  ({len(results)} of {len(candidates)} shown)")
            print()
            for r in results:
                print_result(r, explain=args.explain)
                print()
        return 0

    if args.name_a and args.name_b:
        result = score_names(args.name_a, args.name_b, is_org=args.org)
        if args.as_csv:
            writer = csv.writer(sys.stdout)
            writer.writerow(["name_a", "name_b", "score", "verdict"])
            writer.writerow([result.name_a, result.name_b, result.score, result.verdict])
        else:
            print_result(result, explain=args.explain)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
