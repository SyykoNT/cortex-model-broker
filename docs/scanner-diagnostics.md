# Scanner diagnostics: metadata-only field attribution

## Scope and safety

Diagnostics schema version 2 preserves rule IDs, counts and numeric scanner
locations and adds two fields per location: `field_path` and `field_class`.
Both are selected from static schema paths/classes; no arbitrary JSON key, event
type, item type, value, exception text, `Secret`, `Match`, context or report bytes
is retained. Array indices are normalized to `[]`; the scanner positions still
distinguish repeated occurrences. Labels describe syntax, **not provenance or
credential safety**.

The primary scanner invocation and Capture.safe behavior are unchanged. Every
match still discards the ENTIRE captured value, adds `gitleaks` / `secret`, and
leaves existing reconstruction/acceptance refusal intact. A no-match scan returns
the existing cleaned value unchanged and does not run the attribution parser.
There are no entropy exemptions, span-redaction rules or provider-field exceptions.

Attribution uses the exact in-memory ensure_ascii JSON passed to the scanner.
A bounded structural parser records string-member spans; it does not search for
matching value text. The body string's exact JSON escape boundaries map nested
SSE/JSON source positions back to outer scanner bytes. Unicode, escaped quotes,
backslashes, controls, surrogate pairs, repeated values and duplicated body /
reconstructed representations are handled without guessing.

## Supported labels

Examples (prefixes are static, indices normalized):

| Field path | Field class |
| --- | --- |
| `request.instructions`, `request.input[].content`, `request.input[].output` | `request_content` |
| `request.input[].id`, `request.input[].call_id` | `request_identifier` |
| `body.sse[].response.id`, `reconstructed.response.id` | `response_id` |
| `body.sse[].item.id`, `reconstructed.response.output[].id` | `message_id`, `reasoning_id`, or `function_call_id`, selected by a whitelisted item type |
| `body.sse[].item.call_id` | `function_call_id` |
| `body.sse[].item.encrypted_content` | `encrypted_reasoning`, only for reasoning items |
| `reconstructed.response.output[].content[].text` | `output_text` or `reasoning_text`, selected by a whitelisted part type |
| `body.sse[].delta` | `output_text`, `reasoning_text` or `function_arguments`, selected by a whitelisted event type |
| `body.sse[].item_id` | `output_item_reference`; do not infer a more specific item type |

The same response/item paths are supported under `reconstructed.events[]` and
`body.sse[].response`; a JSON body must explicitly have `object: "response"` to
receive the `body.json` response path. Function arguments remain opaque strings:
JSON-looking content is not recursively treated as provider schema. Tool schemas,
unknown properties and unknown item/event types receive `unknown`.

## Coordinate limitations discovered with the real pinned scanner

Certified against gitleaks **8.30.1**, not hypothetical conventional columns:

* First-line columns are UTF-8 byte positions, one-based, with inclusive ends.
  Capture emits ASCII, unindented JSON, so byte and character boundaries agree
  outside the encoded body string.
* After a real LF, gitleaks counts the preceding LF as column 1: a token after
  `abc\nhello ` begins at reported column 8, not 7. Actual multiline scanner
  inputs are unsupported and remain unknown; SSE newlines are escaped in the
  outer input, so supported SSE captures still occupy scanner line 1.
* **Large stdin inputs have fragment-local columns without a retained fragment
  origin.** Real tests reproduced a token near byte 65,566 reported near column
  3,703. It is unsafe to index a whole capture with such coordinates. Attribution
  therefore requires the ENTIRE encoded scanner input to be at most **25,000
  bytes**. The primary scanner continues scanning larger values unchanged, but
  every field attribution is `unknown`. This cap must not be raised from a few
  favorable observations or by assuming all findings came from the first chunk.
  The source-backed bound is pinned to upstream v8.30.1 commit
  `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`:
  [`sources/file.go:183–224`](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/sources/file.go#L183-L224)
  uses ordinary short reads, then
  [`sources/common.go:58–124`](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/sources/common.go#L58-L124)
  extends each nonempty read by at most 25,000 bytes. With no actual newline and
  total input at most 25,000 bytes, EOF occurs in the first fragment regardless
  of initial read size. The binary's behavior is regression-tested; this is not
  a claim of reproducible-build equivalence to that upstream commit.
  A 30,048-byte fixture with a 4,096-byte pipe reproduced output text being
  mislabeled as encrypted reasoning under the rejected 32,768-byte cap.
  Permanent real-scanner tests cover that case and 24,999/25,000/25,001-byte
  boundaries with the same small pipe. Sender write sizes never prove read sizes.
* Nonempty/missing/unrecognized scanner `Tags`, including recursively decoded
  findings, produce unknown attribution. No tag strings are retained.
* This implementation is tested with the pinned binary; it does not establish
  coordinate compatibility with other scanner versions/configurations.

Other bounds: 4,096 parsed value nodes shared across outer/body parses, nesting
at most 48, body string at most 32,768 characters (also constrained by encoded
input). No parser runs for inputs over the attribution cap. Traversal and escape
mapping are linear in bounded input; interval lookup uses binary search.

A finding must fit entirely inside ONE known scalar member and overlap its value
content. Known key/colon syntax can be included because some scanner rules match
an assignment. Key-only, cross-field, cross-frame, out-of-range, unknown, overlapping
or unsupported spans remain unknown. Cross-data-line SSE members are deliberately
unsupported. Duplicate JSON keys, malformed/unterminated SSE, conflicting event
names and invalid DONE framing make the affected source unknown. Parsing or
budget failure never relaxes whole-value redaction or promotes a scan to success.

## Interpretation and use

This repair cannot retrospectively classify the discarded historical capture.
Its four generic-api-key detections remain **field identity unknown**, not false
positives. Its input length and any fragment origins were not retained.

A new authorized diagnostic attempt can identify supported schema fields, but is
not guaranteed to do so if its capture exceeds the cap or hits another unsupported
case. A field label alone does not authorize an exception. Any future opaque-ID /
encrypted-reasoning entropy policy requires separate evidence, review and approval.
If a new report is unknown due to a larger input, a separately reviewed scanner
coordinate/fragment protocol is needed; do not silently alter scanning or infer
field identities from repeated token values.
