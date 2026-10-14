# Scanner diagnostics: conservative content-verified attribution

## Safety contract

Schema version 4 retains PRIMARY rule IDs, counts and numeric scanner locations. Each
location adds `field_path: "unknown"`, `field_class: "unknown"`, a static
`attribution_reason`, and `coordinate_space: "scanner_local"`. Known field labels
appear only in independent secondary `rules[].field_evidence`, never on primary
locations. The top-level `encoded_byte_count` records
the exact scanner input length (null only when the projector has no byte input).
Labels describe supported syntax, **not authenticated provider provenance or
credential safety**. No field exceptions, entropy exemptions, partial redaction,
per-field scanning, acceptance or reconstruction changes are introduced.

Every detection still discards the ENTIRE captured value, adds `gitleaks` /
`secret`, and preserves existing reconstruction refusal. Clean scans return the
existing cleaned value and do not run attribution. Malformed, oversized, timed
out or failed primary scanner reports retain `redaction_scanner_unavailable`.

## Private report transport

The primary whole-input command retains `--redact`, its detectors, environment,
4,000,000-byte report cap, 4,096-finding validation and 30-second timeout. A clean
validated primary returns immediately. Primary invalid reports, transport failures,
timeouts and unavailable executables retain their ordinary failure behavior;
none start the optional pass. Whole-value detection/redaction is authoritative.

ONLY a validated primary detection permits a second, same-input invocation with
`--redact=0`, using the same limits. It adds at most another scanner timeout plus
bounded parsing/proof work. No report file is created; stderr remains `/dev/null`.
A diagnostic overflow, timeout, exception, clean/invalid report, or total/per-rule
count mismatch changes ONLY diagnostic labels to unknown with a static reason.
It NEVER refuses an already valid primary detection, changes primary counts/rules/
locations, accepts a detected value, or suppresses ordinary primary failures.
The larger raw report can therefore lose attribution but not the primary outcome.
The secondary report and its complete raw Match remain transient private memory.

The JSON parser separates private `(public-location-reference, Match, supported-
tags)` evidence from the public whitelist. `Secret`, `Line`, `Description`, tag
text, context, dynamic keys and all other raw finding fields are discarded. Raw
report bytes and values are never returned by `scan`, printed, logged or persisted.
The internal `run_scanner` primitive returns its bounded private report to the
projector only; it must not be used as a logging API. Parser failure returns a
sentinel before a fresh sanitized Refusal is raised, preventing JSONDecodeError's
raw `.doc` or private traceback from surviving in exception chaining. Transport
failure after successful process launch similarly clears its report buffer before
raising outside its handler. **Bounded claim:** the inherited missing-executable
`OSError` occurs before that transport cleanup boundary; its traceback may retain
input in frame locals. This candidate deliberately preserves that primary failure
behavior and does not claim traceback-input confinement for launch failures.
This is lifecycle confinement within those boundaries, not a claim that Python strings are securely erased
or that process-memory/core-dump inspection cannot see input already in memory.

## Origin proof (not coordinate interpretation)

Gitleaks 8.30.1 stdin fragments reset columns without publishing a byte origin.
Even a Match equal to the input at those reported columns is **not evidence of
origin**: a later fragment can contain the same value in another field. The
previous 25,000-byte single-fragment coordinate cap is therefore superseded by a
separate content proof; numeric coordinates are still always marked scanner-local.
No global coordinates or unique-origin claim is synthesized.

1. Parse the exact serialized ASCII input into nonoverlapping, whitelisted static
   scalar-member spans; map the nested body JSON/SSE escape boundaries exactly.
2. Require empty scanner Tags, a nonempty ASCII string Match, line 1 at both ends,
   and byte length equal to the reported inclusive column width. Width is only an
   integrity check, NEVER an offset. Missing/malformed/truncated evidence stays
   unknown. No stripping, normalization, decoding, regex search, Secret fallback,
   or substring of Match is allowed.
3. Find **every exact occurrence of the whole Match** in the full encoded input,
   including overlapping occurrences. Each must lie wholly in one admitted member
   and overlap that member's **nonempty** value (assignment syntax may be included).
   A complete assignment to an empty string cannot establish value overlap.
4. Attribute only after search reaches the end and every occurrence agrees on
   BOTH the same static normalized path AND class. Any unknown/cross-field
   occurrence or disagreement yields unknown. Duplicates under the same `[]`
   path/class may be attributed; identical values across request/output/opaque
   classes or body/reconstructed paths cannot be disambiguated and remain unknown.
5. Exhausted work/occurrence limits and structure errors stay unknown. A metadata
   exception never promotes a match to success or changes whole-value redaction.

The trusted pinned scanner emits complete Match for untagged direct findings
(`detect/detect.go:452–501` in upstream commit
`83d9cd684c87d95d656c1458ef04895a7f1cbd8e`). That code trims actual LF at regex
boundaries; supported serialized capture input contains no actual CR/LF. Decoded
findings are excluded regardless of whether their text also appears literally.
A forged report that consistently forges Match and width is outside the trusted
scanner boundary; this proof does not authenticate arbitrary scanner implementations.

## Cross-pass association (no coordinate or ordering join)

Count and rule equality admit diagnostic evidence; they DO NOT establish finding
identity. Different stdin fragment splits can change WHICH matches survive, not
just their order. Report order, equal numeric coordinates, and even uniformly
proved secondary labels cannot establish equal finding sets across the scans.
Never zip primary and secondary findings or transfer labels between them.

Each admitted rule has a separate `field_evidence` set containing only static
`field_path`, `field_class`, and `attribution_reason` values. These describe the
secondary pass's content proofs, NOT links to any primary location; the set has
no per-field counts or numeric coordinates. Unknown evidence is retained rather
than silently discarded. This allows review of a mixed request/output/encrypted-
reasoning rule without asserting which primary finding came from which field.

Every primary location ALWAYS retains unknown path/class, including when every
secondary finding has the same complete all-occurrence proof. Successful secondary
admission sets `secondary_evidence_unlinked`; a primary unsupported-tags marker
remains `primary_unsupported_tags`. Proof-failure reasons remain in the independent
`field_evidence` set, not on primary locations. Uniform, mixed and partial evidence
all follow the same no-linkage rule. This permits inspection of actual secondary
opaque-field detections but never establishes primary or historical field identity.

Secondary failures publish no `field_evidence`; reasons include `secondary_clean`,
`secondary_invalid_report`, `secondary_mismatch`, and `secondary_unavailable`.
Other association reasons are `primary_unsupported_tags` and the internal initial
`secondary_not_run` label. Ordinary proof reasons below remain unchanged.

## Diagnostic budgets

- Encoded input and decoded body: 4,000,000 bytes/characters, tied to the existing
  report budget rather than increasing to the 64 MB transport ceiling. Larger
  inputs **still undergo full primary scanning**, but attribution is unknown.
- Nodes: `min(65_536, max(4096, encoded_byte_count // 64))`, shared by outer/body
  parses; depth 48. The prior node floor remains; larger captures have a bounded
  input-scaled allowance instead of unbounded tree growth.
- Exact-search work: 64,000,000 charged bytes total per report (the existing
  transport response ceiling). Each search charges remaining input plus Match
  length conservatively; there are at most 4,096 found occurrences per report.
  Exhaustion may leave earlier fully proved findings labeled while later ones are
  unknown; no label is published for an incomplete occurrence search.

Safe reasons are `exact_all_occurrences`, `input_unsupported`, `input_budget`,
`structure_unsupported_or_budget`, `match_unsupported`, `tags_unsupported`,
`match_absent`, `occurrence_outside_field`, `occurrence_ambiguous`, `search_budget`,
`occurrence_budget`, and `attribution_failure`. Structural failure within an
individual body simply leaves its spans unavailable (`occurrence_outside_field`).
Counts and reasons do not disclose source snippets or arbitrary strings.

## Supported static labels

| Field path | Field class |
| --- | --- |
| `request.instructions`, `request.input[].content`, `request.input[].output` | `request_content` |
| `request.input[].id`, `request.input[].call_id` | `request_identifier` |
| `body.sse[].response.id`, `reconstructed.response.id` | `response_id` |
| `body.sse[].item.id`, `reconstructed.response.output[].id` | `message_id`, `reasoning_id`, `function_call_id` (whitelisted item type) |
| `body.sse[].item.call_id` | `function_call_id` |
| `body.sse[].item.encrypted_content` | `encrypted_reasoning` (reasoning items only) |
| `reconstructed.response.output[].content[].text` | `output_text` or `reasoning_text` (whitelisted part type) |
| `body.sse[].delta` | `output_text`, `reasoning_text`, `function_arguments` (whitelisted event type) |
| `body.sse[].item_id` | `output_item_reference` |

Equivalent response/item paths are supported under `reconstructed.events[]` and
`body.sse[].response`. JSON bodies require `object: "response"`. Unknown keys and
types, dynamic schemas, duplicate keys, unsupported framing and cross-data-line
SSE members remain unknown. Function arguments remain opaque strings. Unicode,
escaped quotes, backslashes, controls and surrogate pairs are mapped structurally,
not normalized during Match search.

## Verification and interpretation

Real pinned 8.30.1 tests exercise default and 4,096-byte pipes, 24,999/25,000/25,001
boundaries, the prior 30,048-byte wrong-opaque-field counterexample, 65,536-byte and
1 MiB inputs, the 4 MB diagnostic boundary and full scanning beyond it. Adversarial
tests cover plausible-but-wrong columns, cross-path/class duplicates, same-path
repeats, overlapping matches, Unicode/JSON/SSE escapes, decoded tags, malformed or
truncated Match, work/node/depth/body/input limits, malformed reports, transport
failure and capture/exception non-disclosure. Existing full-value redaction and
FC5 reconstruction/follow-up refusal tests remain required. Auxiliary tests cover
redacted-report-fit/raw-report-overflow with the real binary, real child timeout,
primary clean/failure short-circuiting, secondary clean/malformed/invalid/count/
rule mismatch/exception, reordered mixed-field reports and numeric-coordinate
preservation. A mocked same-input, same-rule/count regression proves that two valid
but different field sets cannot label primary locations, even with uniform
secondary evidence. The full `"encrypted_content": ""` assignment has a direct
proof-API regression; the real pinned scanner reports that empty assignment clean.
None may weaken or redetermine the primary decision.

This candidate cannot classify discarded historical captures. Four historical
generic-api-key detections remain field-identity unknown. No provider attempt is
part of these offline tests. Future opaque-field exemptions need separate trusted
envelope/provenance binding, evidence, review and authorization.
