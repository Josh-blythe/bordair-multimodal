# Real-world attack split

## `attacks.jsonl`

13,230 real attacks collected from a live game where players competed to beat a deployed detector, then anonymised. Each row is one attack string that a human wrote while trying to make the detector leak a password or override its instructions. Schema:

```json
{"source": "castle_bypasses", "text": "...", "expected_detection": true,
 "labels": {"level": 7, "method": "ml"}, "redacted_pii": ["[EMAIL]"]}
```

`source` records which part of the game the attack came from (`castle_attempts`, `castle_bypasses`, `champion_attempts`). `redacted_pii` is present only when the anonymiser replaced something. These come from real human adversaries rather than templates, so they read very differently from the generated layers above: messier, conversational, and often novel.

This is a validation split, not a training layer. It sits alongside Layers 1-4 as the real-world check on whether the dataset's synthetic coverage holds up against a motivated human trying to break a live detector, rather than against held-out generated samples.

## Anonymising the real-world split

Raw player submissions are never published. The scrub process:

1. Table-level filtering. Only the columns that carry attack text were kept (`prompt`, `attacker_input`). Every user table, covering accounts, emails, IP addresses, and payment identifiers, was dropped whole.
2. Identifier stripping. `user_id`, `api_key`, IP address, email, and session-fingerprinting timestamps were removed from each retained row.
3. In-text redaction. The attack text itself was scanned for emails, phone numbers, card-shaped digit runs, national insurance or social security numbers, IP addresses, and self-identifying phrases. Matches were replaced with tagged placeholders such as `[EMAIL]` and `[PHONE]`.
4. Quarantine. Any row that still carried high-risk data after redaction was held back for manual review rather than published automatically.
5. Deduplication. Exact duplicates were collapsed.

Each retained record keeps only the attack text, a few coarse labels (level, method, confidence), and, where a redaction fired, the `redacted_pii` tags.
