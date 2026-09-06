#!/usr/bin/env python3
"""
Entity Name Matcher
====================

A dependency-free fuzzy name-matching tool for KYC / case-review work:
checking whether two names (people or organizations) plausibly refer to
the same entity, given nicknames, initials, reordering, transliteration
drift, typos, and legal-suffix noise.

No network calls, no third-party packages -- stdlib only, so it runs
anywhere Python 3 does.

Usage
-----
Compare two names directly:

    python entity_name_matcher.py "Robert J. Smith" "Bob Smith"

Compare one query name against a list (one name per line, or CSV with
a "name" column) and get ranked candidates:

    python entity_name_matcher.py --query "R. Smith" --list names.txt
    python entity_name_matcher.py --query "R. Smith" --list names.csv --top 5

Show the score breakdown instead of just the final number:

    python entity_name_matcher.py "Bob Smith" "Robert Smith" --explain

Treat names as organizations (adds legal-suffix stripping: Inc, LLC, Ltd...):

    python entity_name_matcher.py "Acme Trading Co." "ACME TRADING, LLC" --org

As a library:

    from entity_name_matcher import score_names
    result = score_names("Bob Smith", "Robert Smith")
    print(result.score, result.verdict)
"""

from __future__ import annotations

import argparse
import csv
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
# Public API
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fuzzy-match entity/person names for KYC and case-review work.",
    )
    parser.add_argument("name_a", nargs="?", help="first name to compare")
    parser.add_argument("name_b", nargs="?", help="second name to compare")
    parser.add_argument("--query", help="a single name to compare against --list")
    parser.add_argument("--list", dest="list_path", help="path to a .txt (one name/line) or .csv (with a 'name' column) file of candidate names")
    parser.add_argument("--top", type=int, default=10, help="max candidates to show when using --list (default 10)")
    parser.add_argument("--threshold", type=float, default=0.0, help="only show results at or above this score when using --list")
    parser.add_argument("--org", action="store_true", help="treat names as organizations (strips legal suffixes like Inc/LLC/Ltd)")
    parser.add_argument("--explain", action="store_true", help="show the score breakdown, not just the final number")
    parser.add_argument("--csv", dest="as_csv", action="store_true", help="print results as CSV (name,score,verdict)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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
