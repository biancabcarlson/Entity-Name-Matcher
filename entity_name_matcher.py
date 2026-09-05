#!/usr/bin/env python3
"""
entity_name_matcher.py
Flags likely-duplicate names in a list using Levenshtein distance similarity.
Outputs a review list for a human to confirm — makes no determination itself.

Usage:
    python entity_name_matcher.py names.txt --threshold 0.82 -o matches.csv

Input (names.txt) — SYNTHETIC EXAMPLE, one name per line:
Jonathan A. Smith
Jon Smith
Maria Garcia-Lopez
Maria Garcia Lopez
Robert Chen
Rob Chen Jr.
"""

import csv
import argparse


def levenshtein(a, b):
    a, b = a.lower(), b.lower()
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j-1] + 1, prev[j-1] + cost))
        prev = curr
    return prev[-1]


def similarity(a, b):
    dist = levenshtein(a, b)
    longest = max(len(a), len(b))
    return 1 - (dist / longest) if longest else 1.0


def find_matches(names, threshold):
    matches = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            score = similarity(names[i], names[j])
            if score >= threshold:
                matches.append((names[i], names[j], round(score, 3)))
    return sorted(matches, key=lambda x: -x[2])


def main():
    ap = argparse.ArgumentParser(description="Flag likely-duplicate names for manual review.")
    ap.add_argument("input", help="Text file, one name per line")
    ap.add_argument("--threshold", type=float, default=0.80,
                     help="Similarity threshold 0-1 (default: 0.80)")
    ap.add_argument("-o", "--output", default="matches.csv")
    args = ap.parse_args()

    with open(args.input) as f:
        names = [line.strip() for line in f if line.strip()]

    matches = find_matches(names, args.threshold)

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["name_a", "name_b", "similarity_score"])
        writer.writerows(matches)

    print(f"{len(matches)} candidate pairs written to {args.output} — review manually before acting.")


if __name__ == "__main__":
    main()
