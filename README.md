# Entity Name Matcher

A dependency-free fuzzy name-matching tool for KYC and case-review work:
checking whether two names — people or organizations — plausibly refer to
the same entity, given nicknames, initials, reordered or dropped tokens,
transliteration drift, typos, and legal-suffix noise.

No network calls, no third-party packages. The CLI is Python stdlib only;
the browser version is plain HTML/CSS/JS with the same scoring logic
ported over, and nothing you type in it ever leaves your browser.

## Contents

```
entity-name-matcher/
├── entity_name_matcher.py   # CLI + importable library
├── index.html               # browser version, same scoring logic in JS
└── README.md
```

## Why this exists

Names in real case data rarely match character-for-character even when
they're the same person or entity:

- **Nicknames** — "Bob Smith" vs "Robert Smith"
- **Initials** — "R. J. Smith" vs "Robert James Smith"
- **Reordering** — "Smith, Robert" vs "Robert Smith"
- **Dropped/extra tokens** — a missing middle name, a "Jr." on one side only
- **Transliteration/diacritics** — "José González" vs "Jose Gonzalez"
- **Legal-suffix noise** on organizations — "Acme Trading Co." vs "ACME
  TRADING, LLC"

A plain string-equality or single-metric string-distance check either
misses these or over-triggers on them. This tool combines three
complementary signals into one score so you get a usable single number
plus a breakdown of *why*.

## How the score is built

For each pair of names:

1. **Normalize** — fold accents/diacritics to plain ASCII, lowercase, strip
   punctuation, tokenize. Strip generational suffixes (Jr/Sr/II/III) for
   people, or legal suffixes (Inc/LLC/Ltd/Corp/GmbH/...) for organizations
   when `--org` / the org checkbox is used.
2. **Nicknames** — a built-in table of ~90 common English given-name
   diminutives (Bob→Robert, Liz→Elizabeth, Sasha→Alexander, etc.) is used
   to canonicalize tokens before comparing them.
3. **Three component scores**, each 0–100:
   - `token_sort` — sort each name's tokens alphabetically, rejoin, and
     run a sequence-similarity ratio. Order-independent.
   - `token_set` — Jaccard overlap of the (nickname-canonicalized) token
     sets. Tolerant of dropped or extra tokens.
   - `pairwise` — greedily pairs each token in the shorter name with its
     best match in the longer name (nickname-aware, and treating a single
     initial as matching any token that starts with the same letter, e.g.
     "R." matches "Bob" via its canonical form "Robert"), then averages
     the pair scores. This is what makes "R. Smith" score well against
     "Robert James Smith".
4. **Weighted combination**: `0.45 × pairwise + 0.30 × token_sort + 0.25 ×
   token_set`, capped at 100.
5. **Verdict buckets**: ≥85 `match`, ≥70 `likely match`, ≥50 `possible
   match`, else `no match`. These thresholds (and the weights) are plain
   constants at the top of the scoring code — tune them for your own case
   mix.

This is a heuristic screening aid, not a legal or compliance
determination. A high score means "worth a human look"; a low score on
short or sparse names (e.g. single-token company names) is worth a second
glance too, since the algorithm has less to work with. Always confirm any
real match with an authoritative source before acting on it.

## Usage — CLI (`entity_name_matcher.py`)

Compare two names directly:

```bash
python entity_name_matcher.py "Robert J. Smith" "Bob Smith"
```

```
'Robert J. Smith' vs 'Bob Smith'
  score:   82.5/100  (likely match)
```

Show the breakdown:

```bash
python entity_name_matcher.py "Bob Smith" "Robert Smith" --explain
```

```
'Bob Smith' vs 'Robert Smith'
  score:   92.9/100  (match)
    token_sort: 76.2
     token_set: 100.0
      pairwise: 100.0
```

Rank a query name against a list (`.txt`, one name per line, or `.csv`
with a `name` column):

```bash
python entity_name_matcher.py --query "R. Smith" --list candidates.txt --top 5
```

Organization names (strips Inc/LLC/Ltd/Corp/etc. before comparing):

```bash
python entity_name_matcher.py "Acme Trading Co." "ACME TRADING, LLC" --org
```

CSV output, for piping into another tool:

```bash
python entity_name_matcher.py --query "Bob Smith" --list candidates.csv --csv --threshold 50
```

As a library:

```python
from entity_name_matcher import score_names, rank_candidates

result = score_names("Bob Smith", "Robert Smith")
print(result.score, result.verdict, result.components)

ranked = rank_candidates("R. Smith", ["Robert Smith", "Roberta Smith", "Michael Jones"])
```

Run `python entity_name_matcher.py --help` for the full flag list.

## Usage — browser (`index.html`)

Open `index.html` directly in a browser (no build step, no server). Two
modes, matching the CLI's two modes:

- **Compare two names** — one score, with the same token-sort / token-set
  / pairwise breakdown as `--explain`.
- **Match against a list** — paste a query name and a candidate list (one
  per line), rank and filter by score.

The JS port uses an LCS-based approximation of the string-similarity
ratio (rather than Python's `difflib.SequenceMatcher`), so scores can
differ by a point or two from the CLI on edge cases — the verdict
buckets and overall behavior match.

## Extending

- **More nicknames**: add entries to the `NICKNAMES` dict (Python) and
  the matching `NICKNAMES` object (JS) — keep both in sync.
- **Other languages**: the nickname table and suffix lists are
  English-centric; swap or extend them for other naming conventions.
- **Different weighting**: adjust `WEIGHTS` / `THRESHOLDS` at the top of
  `entity_name_matcher.py` (and the equivalent constants in `index.html`)
  to match your own precision/recall tradeoff.

## Used alongside

Built to be worked as a practice case together with the
[simulated-account](https://github.com/biancabcarlson/simulated-account)
fixture and the rest of the investigator tool series — the fixture's
Security & KYC tab links here directly to check name variants on a
flagged payee.

- [Case Calculator](https://biancabcarlson.github.io/Case-Calculator/)
- [Report Template Filler](https://biancabcarlson.github.io/Report-Template-Filler/)
- [OSINT Query Fanout](https://biancabcarlson.github.io/OSINT-Query-Fanout/)
- [Case Doc Tracker](https://biancabcarlson.github.io/Case-Doc-Tracker/)
- [Case Timeline Builder](https://biancabcarlson.github.io/Case-Timeline-Builder/)
