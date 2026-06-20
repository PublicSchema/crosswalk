Below is a solid **v0.1 spec** for a Rust-based CEL mapping library that can be wrapped for **JavaScript/WASM** and **Python**.

I’ll assume the goal is:

```text id="cu22cr"
source system payload
→ canonical mapping spec
→ CEL expressions + standard host functions
→ normalized canonical object(s)
```

CEL is a reasonable core because it is designed to be embedded, extended with application-specific functions, and run safely/portably inside applications. ([Common Expression Language][1]) `cel-rust` already supports custom functions, which fits the Rust-core idea. ([GitHub][2]) For JS/browser wrapping, `wasm-bindgen` is the obvious path because it facilitates high-level Rust ↔ WebAssembly ↔ JavaScript interaction. ([Rust and WebAssembly][3]) For Python, PyO3 is the obvious native-extension route because it supports wrapping Rust code for Python. ([PyO3][4])

---

# Initial Spec: CEL Mapping Runtime

## 1. Purpose

This library provides a deterministic, embeddable mapping runtime for transforming data from external systems into canonical objects.

The library does **not** try to be a full ETL orchestrator. It provides:

```text id="msg57s"
1. A declarative mapping format
2. A CEL expression evaluator
3. A standard library of ETL-safe CEL functions
4. Runtime validation and error reporting
5. Rust core API
6. JavaScript/WASM wrapper
7. Python wrapper
```

The runtime should be usable for mappings such as:

```yaml id="v3qi7l"
records:
  person:
    foreach: "source.members"
    as: "member"
    fields:
      id: "id.make('person', source.__id, index)"
      name: "text.trim(member.name)"
      birth_date: "date.parse(member.dob, 'yyyy-MM-dd')"
      gender: "code.map('odk.gender', member.sex)"
```

---

# 2. Design Principles

## 2.1 CEL computes values

CEL expressions should answer:

```text id="qmqkce"
What value should this field have?
```

Example:

```cel id="fxdgr0"
text.trim(source.first_name) + " " + text.trim(source.last_name)
```

## 2.2 Mapping YAML controls structure

The mapping spec should answer:

```text id="10kqf5"
Which records are emitted?
Which source list is iterated?
Which fields are written?
Which expressions are evaluated?
```

Example:

```yaml id="t5ezie"
records:
  people:
    foreach: "source.members"
    as: "member"
    fields:
      name: "text.trim(member.name)"
```

## 2.3 Host functions are deterministic

Functions exposed to CEL must be deterministic unless explicitly declared otherwise.

Avoid hidden global state.

Bad:

```cel id="gbpl8m"
date.now()
```

Better:

```cel id="gotbmp"
ctx.now
```

Where `ctx.now` is passed into the evaluation context by the host.

## 2.4 No I/O inside CEL

CEL functions should not directly call databases, HTTP APIs, filesystems, or external services.

Allowed:

```cel id="9fwfib"
code.map("odk.gender", source.sex)
```

But `code.map` should use a mapping table already loaded into the runtime context.

Not allowed:

```cel id="mo5t1y"
http.get("https://...")
```

## 2.5 Prefer explicit null behavior

Every function must define what happens for:

```text id="42p47i"
null
missing field
empty string
wrong type
invalid value
```

The runtime should support both:

```text id="7zpzn3"
strict mode
lenient mode
```

## 2.6 Missing-field semantics

Mappings should be pleasant to write, so v0.1 treats a missing field lookup as a first-class mapping value, not as an immediate CEL crash.

Normative rule:

```text id="nf6ckc"
source.missing_field
member.missing_field
ctx.missing_field
```

must evaluate to an internal `Missing` sentinel. Helper functions such as `present`, `missing`, `blank`, `coalesce`, `default`, and `require` must be able to receive that sentinel.

At public output boundaries, `Missing` is never serialized. It must become either:

```text id="9mtcmi"
null
an omitted field
a MappingError
```

depending on field-level and mapping-level error policy.

Implementation note: if the chosen CEL engine raises an unknown-attribute error before host functions receive the argument, the runtime wrapper must translate that error into `Missing` for data-object field access. Unknown variables and unknown functions should still be compile/evaluation errors.

For deeply nested optional paths, both styles should work:

```cel id="7blxsy"
present(source.person.name)
map.get(source, "person.name")
```

---

# 3. Runtime Data Model

## 3.1 Supported value types

The public boundary should use JSON-compatible values:

```text id="8fa1a3"
null
boolean
number
string
array
object/map
```

Internally, the Rust runtime may use richer types, but wrappers should expose predictable JSON values.

Recommended internal value model:

```rust id="om3js2"
enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}
```

Avoid exposing Rust-specific numeric ambiguity to JS/Python users.

## 3.2 Numeric portability

The public JSON/WASM/Python boundary must be deterministic and loss-aware.

For v0.1:

```text id="qyvsn1"
safe integer range: -(2^53 - 1) through 2^53 - 1
finite floats only
NaN and Infinity are invalid
```

Rules:

```text id="l1zm2k"
Rust Int inside the safe integer range → JSON number
Rust Int outside the safe integer range → error by default
Rust Float that is finite → JSON number
Rust Float NaN/Infinity → error
decimal precision requirements → represent as string in source/canonical schema, or add Decimal later
```

If a project needs large integers such as database IDs or national IDs, mappings should keep them as strings:

```cel id="wy1jjm"
type.string(source.large_id)
```

Canonical serialization for hashing, tests, and wrappers must preserve numeric kind:

```text id="i66ifs"
1      as integer 1
1.0    as float 1.0
"1"    as string "1"
```

## 3.3 Dates and times

For v0.1, dates should be returned as strings:

```text id="m1y748"
date:      YYYY-MM-DD
datetime:  ISO-8601 / RFC3339 string
time:      HH:mm:ss
```

This avoids cross-language weirdness between Rust, JavaScript, Python, and WASM.

---

# 4. CEL Evaluation Context

Every expression receives a context object.

## 4.1 Standard variables

| Variable | Meaning                                               |
| -------- | ----------------------------------------------------- |
| `source` | Current source object                                 |
| `root`   | Original root input object                            |
| `item`   | Current item in a `foreach`, if any                   |
| `index`  | Current zero-based loop index, if any                 |
| `ctx`    | Runtime context/constants                             |
| `vars`   | User-defined intermediate variables                   |
| `target` | Reserved for future use                               |

Example:

```cel id="q7l2vm"
text.trim(item.name)
```

or:

```cel id="z2mikz"
id.make("person", root.__id, index)
```

## 4.2 Variable and field evaluation order

For v0.1, keep evaluation order simple and deterministic:

```text id="0qfj5m"
1. Evaluate record-level vars before fields.
2. Evaluate fields in YAML order.
3. Do not expose partially built output through target.
4. Do not allow field expressions to depend on sibling fields.
```

`vars` may depend on earlier `vars` in the same map, also in YAML order. Cycles are therefore invalid by construction if a variable references one declared later. The compiler should reject references to unknown `vars` keys when it can detect them.

Example:

```yaml id="yunlfl"
people:
  foreach: "source.members"
  as: "member"
  vars:
    clean_name: "text.normalize_space(member.name)"
    canonical_gender: "code.map_or_null('odk.gender', member.sex)"
  fields:
    name: "vars.clean_name"
    gender: "vars.canonical_gender"
```

`target` is reserved because allowing fields to read partially built records makes mappings order-sensitive and harder to optimize. A future version may introduce explicit field dependencies.

## 4.3 Runtime context

Example:

```json id="dg57m0"
{
  "ctx": {
    "now": "2026-05-03T10:30:00+07:00",
    "timezone": "Asia/Bangkok",
    "locale": "en",
    "mapping_id": "odk-household-to-canonical-v1",
    "source_system": "odk",
    "target_model": "canonical"
  }
}
```

---

# 5. Mapping Spec v0.1

## 5.1 Minimal shape

```yaml id="b97nny"
version: 0.1
name: odk_household_to_canonical
source_system: odk
target_model: canonical.household_bundle

records:
  household:
    emit: "true"
    fields:
      id: "id.make('household', source.__id)"
      village: "text.trim(source.village)"
      submitted_at: "date.parse_datetime(source.__system.submissionDate)"

  people:
    foreach: "source.members"
    as: "member"
    when: "present(member.name)"
    fields:
      id: "id.make('person', source.__id, index)"
      household_id: "id.make('household', source.__id)"
      name: "text.trim(member.name)"
      gender: "code.map('odk.gender', member.sex)"
      birth_date: "date.parse(member.dob, 'yyyy-MM-dd')"
```

## 5.2 Record keys

| Key       |                Type | Meaning                            |
| --------- | ------------------: | ---------------------------------- |
| `emit`    | CEL bool expression | Whether to emit a singleton record |
| `foreach` | CEL list expression | Source collection to iterate       |
| `as`      |              string | Variable name for current item     |
| `when`    | CEL bool expression | Per-record filter                  |
| `fields`  |                 map | Target fields and CEL expressions  |
| `vars`    |                 map | Reusable intermediate expressions  |
| `errors`  |              config | Error policy                       |

## 5.3 Field expression result

Each field expression returns exactly one value.

That value may be:

```text id="c56w7b"
scalar
list
object
null
```

Example object result:

```yaml id="5r3v7w"
name:
  expr: "person_name.parse(source.full_name)"
```

Possible output:

```json id="1kpqdi"
{
  "given": "Amina",
  "family": "Diallo"
}
```

## 5.4 Field configuration

A field may be written as a string shorthand:

```yaml id="aw04je"
name: "text.trim(member.name)"
```

which is equivalent to:

```yaml id="b6sgae"
name:
  expr: "text.trim(member.name)"
  required: false
```

Structured field config supports:

| Key        | Type           | Meaning                                      |
| ---------- | -------------- | -------------------------------------------- |
| `expr`     | CEL expression | Field value expression                       |
| `required` | bool           | Whether null, missing, or failed value fails |
| `on_error` | string         | Field-level behavior on expression error     |
| `default`  | any            | Fallback value for `on_error: default`       |

Supported `on_error` values:

```text id="f9bchy"
fail
null
omit
default
```

Defaults:

```text id="0aj81j"
required: false
on_error in strict/collect: fail
on_error in lenient: null
```

Required fields always behave as `on_error: fail`. A field is also required when its expression uses `require(...)` or `validate.required(...)` and that call fails.

---

# 6. Function Naming Convention

Use namespaces.

Recommended format:

```text id="lkp8vv"
text.trim(...)
date.parse(...)
code.map(...)
id.make(...)
geo.point(...)
```

If the chosen CEL Rust implementation does not support dotted names cleanly, expose aliases:

```text id="3te8hf"
text_trim(...)
date_parse(...)
code_map(...)
id_make(...)
geo_point(...)
```

But the canonical spec should use dotted names.

---

# 7. Standard CEL Function Library

This is the most important part.

## 7.1 Presence and null handling

These functions should exist from day one.

### `present(value) -> bool`

Returns `true` if value is not null, not missing, and not an empty string.

```cel id="fwrvkf"
present(source.name)
```

Rules:

```text id="zi8px8"
null       → false
missing    → false
""         → false
"   "      → false
[]         → false
{}         → false
0          → true
false      → true
```

### `missing(value) -> bool`

Opposite of `present`.

```cel id="8g4kcn"
missing(source.phone)
```

### `blank(value) -> bool`

Returns true for null, missing, or whitespace-only string.

```cel id="h3eic7"
blank(source.comment)
```

### `coalesce(values...) -> any`

Returns the first present value.

```cel id="tl9zxc"
coalesce(source.phone, source.alt_phone, "unknown")
```

### `default(value, fallback) -> any`

Returns `fallback` if `value` is null, missing, or blank.

```cel id="s1hrmv"
default(source.country, "KE")
```

### `require(value, message?) -> any`

Returns value if present, otherwise raises a validation error.

```cel id="0p379i"
require(source.name, "name is required")
```

### `null_if(value, match) -> any`

Returns null when `value == match`.

```cel id="4nn98g"
null_if(source.age, "")
```

### `null_if_blank(value) -> any`

```cel id="g1xz90"
null_if_blank(source.middle_name)
```

---

## 7.2 Type conversion

Namespace: `type`.

### `type.string(value) -> string`

Converts value to string.

```cel id="vjbjh3"
type.string(source.id)
```

### `type.int(value) -> int`

Parses integer.

```cel id="xzs86j"
type.int(source.age)
```

### `type.float(value) -> double`

Parses decimal/float.

```cel id="jpmkoh"
type.float(source.weight)
```

### `type.bool(value) -> bool`

Parses boolean.

Accepted examples:

```text id="z1zxu7"
true, false
"true", "false"
"yes", "no"
"y", "n"
"1", "0"
1, 0
```

### `type.list(value) -> list`

Converts value to list.

Rules:

```text id="ubyi9p"
null → []
list → list
other → [value]
```

### `type.map(value) -> map`

Ensures value is an object/map.

### `type.is_string(value) -> bool`

### `type.is_number(value) -> bool`

### `type.is_bool(value) -> bool`

### `type.is_list(value) -> bool`

### `type.is_map(value) -> bool`

---

## 7.3 Text normalization

Namespace: `text`.

### `text.trim(value) -> string`

```cel id="2c5gvm"
text.trim(source.name)
```

### `text.lower(value) -> string`

### `text.upper(value) -> string`

### `text.title(value) -> string`

Useful for names.

```cel id="y3ppnk"
text.title(source.full_name)
```

### `text.normalize_space(value) -> string`

Collapses repeated whitespace.

```cel id="35nqf0"
text.normalize_space("  Amina   Diallo ")
```

Returns:

```text id="ze9tru"
"Amina Diallo"
```

### `text.remove_accents(value) -> string`

```cel id="h5cq7p"
text.remove_accents("José")
```

Returns:

```text id="j1nc5t"
"Jose"
```

### `text.slug(value) -> string`

```cel id="zzn2z2"
text.slug("Household Member")
```

Returns:

```text id="85abdd"
"household-member"
```

### `text.replace(value, from, to) -> string`

### `text.regex_replace(value, pattern, replacement) -> string`

### `text.matches(value, pattern) -> bool`

### `text.split(value, separator) -> list<string>`

### `text.join(values, separator) -> string`

### `text.left(value, n) -> string`

### `text.right(value, n) -> string`

### `text.substr(value, start, length?) -> string`

### `text.length(value) -> int`

### `text.contains(value, needle) -> bool`

### `text.starts_with(value, prefix) -> bool`

### `text.ends_with(value, suffix) -> bool`

---

## 7.4 Name parsing

Namespace: `name`.

These should be conservative. Name parsing is culturally hard, so do not overpromise.

### `name.full(given, family) -> string`

```cel id="0oyr8f"
name.full(source.first_name, source.last_name)
```

### `name.parts(full_name) -> map`

Returns best-effort object:

```json id="juiyqu"
{
  "given": "Amina",
  "middle": null,
  "family": "Diallo"
}
```

### `name.initials(value) -> string`

```cel id="w36x71"
name.initials(source.full_name)
```

---

## 7.5 Date and time

Namespace: `date`.

For v0.1, return strings, not native Date objects.

### `date.parse(value, format?) -> string`

Returns `YYYY-MM-DD`.

```cel id="ox5rnh"
date.parse(source.dob, "yyyy-MM-dd")
```

Format strings use the Unicode/ICU date pattern dialect, not Rust `strftime`.

Common v0.1 tokens:

```text id="xsdobm"
yyyy  four-digit year
MM    two-digit month
dd    two-digit day
HH    two-digit hour, 00-23
mm    two-digit minute
ss    two-digit second
XXX   numeric timezone offset, such as +07:00
```

The runtime should translate these patterns internally for the chosen Rust date library.

### `date.parse_datetime(value, format?) -> string`

Returns RFC3339 datetime string.

```cel id="tomyrb"
date.parse_datetime(source.submission_time)
```

Datetime rules:

```text id="aus7rt"
datetime with explicit offset → preserve the instant and serialize as RFC3339
datetime without offset + ctx.timezone present → interpret in ctx.timezone
datetime without offset + no ctx.timezone → error in strict/collect, warning+null in lenient
date-only input passed to parse_datetime → error unless a format explicitly includes only a date and a default time policy is configured
```

### `date.format(value, format) -> string`

```cel id="yv0yo2"
date.format(source.dob, "yyyy-MM")
```

### `date.today() -> string`

I would **not** allow this by default.

Prefer:

```cel id="kt5f8f"
ctx.today
```

If included, `date.today()` must read from runtime context, not system clock.

### `date.age_on(birth_date, reference_date) -> int`

```cel id="517w4j"
date.age_on(source.dob, ctx.today)
```

### `date.years_between(start, end) -> int`

### `date.days_between(start, end) -> int`

### `date.add_days(date, days) -> string`

### `date.add_months(date, months) -> string`

### `date.start_of_month(date) -> string`

### `date.end_of_month(date) -> string`

### `date.is_valid(value, format?) -> bool`

### `date.is_before(a, b) -> bool`

### `date.is_after(a, b) -> bool`

### `date.min(a, b) -> string`

### `date.max(a, b) -> string`

---

## 7.6 Numbers

Namespace: `num`.

### `num.round(value, digits?) -> number`

### `num.floor(value) -> int`

### `num.ceil(value) -> int`

### `num.abs(value) -> number`

### `num.min(values...) -> number`

### `num.max(values...) -> number`

### `num.clamp(value, min, max) -> number`

```cel id="v3s83n"
num.clamp(source.score, 0, 100)
```

### `num.is_valid(value) -> bool`

### `num.parse(value, locale?) -> number`

### `num.percent(part, total) -> double`

### `num.safe_divide(numerator, denominator, fallback?) -> number`

```cel id="06wryx"
num.safe_divide(source.used, source.total, 0)
```

---

## 7.7 Lists

Namespace: `list`.

CEL already has list operations, but ETL needs predictable helper functions.

### `list.compact(values) -> list`

Removes null/blank values.

```cel id="xm0z10"
list.compact([source.phone1, source.phone2])
```

### `list.flatten(values) -> list`

### `list.unique(values) -> list`

### `list.sort(values) -> list`

### `list.first(values) -> any`

### `list.last(values) -> any`

### `list.at(values, index, fallback?) -> any`

### `list.length(values) -> int`

### `list.contains(values, value) -> bool`

### `list.join(values, separator) -> string`

### `list.filter_present(values) -> list`

Same as compact, but clearer in user-facing mappings.

### `list.to_map(values, key_field) -> map`

Example:

```cel id="t1h1kb"
list.to_map(source.members, "id")
```

### Native CEL collection macros

Beyond the `list.*` helpers above, the standard CEL comprehension macros are
available as **methods on any list expression** and may be used directly in
mapping formulas:

| Macro | Meaning |
|-------|---------|
| `xs.all(x, pred)` | `true` if `pred` holds for every element (vacuously `true` for an empty list) |
| `xs.exists(x, pred)` | `true` if `pred` holds for at least one element |
| `xs.exists_one(x, pred)` | `true` if `pred` holds for exactly one element |
| `xs.filter(x, pred)` | the sublist of elements for which `pred` holds |
| `xs.map(x, expr)` | the list of `expr` evaluated for each element |

`size(xs)` and index access (`xs[0]`) are likewise supported. Macros may be
nested and combined with helpers — for example
`source.attributes.filter(a, a.id == 'x')[0].value`, or, to flatten a list of
lists before counting, `size(list_flatten(source.groups.map(g, g.items)))`.

These macros are method calls on a *list-valued expression* (the receiver `xs`
is any expression that evaluates to a list); this is distinct from the `list.*`
helper namespace documented above, whose entries are rewritten to `list_*`
function calls at compile time.

Per CEL semantics the per-element predicate/transform body is evaluated in a
**strict** context: a missing field referenced inside a macro body raises an
error rather than being treated as absent, even when the whole expression is
wrapped in a missing-aware helper such as `coalesce(...)`. For the same reason,
guard a macro whose *receiver* may be absent with an explicit
`present(source.items) ? source.items.filter(...) : []` rather than relying on
`coalesce(...)` to rescue it.

Two practical notes when applying macros to JSON-sourced data:

- **Filter then transform:** chain `xs.filter(x, pred).map(x, expr)` rather than
  the 3-argument `map` form, which is not reliably supported.
- **Integer types:** non-negative JSON integers decode as CEL *unsigned* values,
  which do not directly `==`, or do arithmetic, with signed integer literals
  (`3`, `10`). Compare with an unsigned literal (`x == 3u`) or wrap the value in
  `int(...)` (`int(x) * 2`). String comparisons (the common case for DHIS2 and
  similar sources) are unaffected.

---

## 7.8 Maps and objects

Namespace: `map`.

### `map.get(object, path, fallback?) -> any`

Supports dotted paths.

```cel id="2pzqbi"
map.get(source, "person.name.given")
```

### `map.has(object, path) -> bool`

```cel id="o309wo"
map.has(source, "person.name")
```

### `map.pick(object, keys) -> map`

```cel id="p4h3u5"
map.pick(source, ["id", "name", "dob"])
```

### `map.omit(object, keys) -> map`

### `map.merge(a, b) -> map`

Second map wins.

### `map.deep_merge(a, b) -> map`

Nested merge.

### `map.set(object, path, value) -> map`

Returns a new map.

### `map.keys(object) -> list<string>`

### `map.values(object) -> list<any>`

### `map.entries(object) -> list<map>`

Returns:

```json id="7qadsv"
[
  {"key": "name", "value": "Amina"}
]
```

---

## 7.9 Code systems and vocabulary mapping

Namespace: `code`.

This is central for your project.

### `code.map(system, value) -> string`

Maps source code to canonical code.

```cel id="c8j36y"
code.map("odk.gender", source.sex)
```

Example mapping table:

```yaml id="v5lw5y"
code_systems:
  odk.gender:
    male:
      id: canonical.gender.male
      label:
        en: Male
    female:
      id: canonical.gender.female
      label:
        en: Female
    other:
      id: canonical.gender.other
      label:
        en: Other
```

Scalar entries are allowed only as shorthand in mapping YAML:

```yaml id="tl83vr"
male: canonical.gender.male
```

The compiler must normalize shorthand to the object form above before evaluation.

### `code.map_or_null(system, value) -> string?`

Returns null if no mapping exists.

```cel id="tnj40m"
code.map_or_null("odk.gender", source.sex)
```

### `code.map_or_default(system, value, fallback) -> string`

```cel id="cup30z"
code.map_or_default("odk.gender", source.sex, "canonical.gender.unknown")
```

### `code.label(system, code, locale?) -> string`

```cel id="3epvp8"
code.label("canonical.gender", "canonical.gender.female", "en")
```

### `code.exists(system, value) -> bool`

```cel id="tm6bmx"
code.exists("odk.gender", source.sex)
```

### `code.canonical(system, value) -> map`

Returns structured concept metadata.

```cel id="ixob2o"
code.canonical("odk.gender", source.sex)
```

Possible result:

```json id="n94zlc"
{
  "id": "canonical.gender.female",
  "label": "Female",
  "system": "canonical.gender"
}
```

### `code.reverse_map(system, canonical_value) -> string?`

Useful for target-specific output mappings.

```cel id="8drtcz"
code.reverse_map("openspp.gender", canonical.gender)
```

### `code.normalize(value) -> string`

Normalizes code-ish strings:

```text id="ey6t7j"
" Female " → "female"
"FEMALE"   → "female"
```

---

## 7.10 Identifiers

Namespace: `id`.

### `id.make(prefix, parts...) -> string`

Deterministic ID generation from parts.

```cel id="719q8a"
id.make("person", source.__id, index)
```

Example result:

```text id="r96d72"
person_01h9x7...
```

Recommended implementation:

```text id="ma7ikm"
prefix + "_" + base32(sha256(canonical_json([prefix, parts...])))
```

The hash input must not be a plain string join. It must be a canonical, type-preserving encoding of the prefix and parts.

Recommended v0.1 encoding:

```text id="c3m950"
canonical_json([prefix, parts...])
```

where object keys are sorted, strings are UTF-8, and numeric kind is preserved according to section 3.2. This prevents ambiguous inputs such as `["ab", "c"]` and `["a", "bc"]` from hashing to the same source string.

### `id.uuid_v5(namespace, value) -> string`

Deterministic UUID.

```cel id="eoao2j"
id.uuid_v5("person", source.__id)
```

### `id.hash(value, algorithm?) -> string`

```cel id="08bfkq"
id.hash(source.national_id, "sha256")
```

### `id.slug(prefix, value) -> string`

```cel id="a5ch0w"
id.slug("village", source.village)
```

### `id.clean(value) -> string`

Removes unsafe ID characters.

### `id.is_valid(value, pattern?) -> bool`

---

## 7.11 Person and demographic helpers

Namespace: `person`.

These are optional but useful in social registry / beneficiary / survey systems.

### `person.age(birth_date, reference_date) -> int`

Alias for `date.age_on`.

```cel id="bf8brx"
person.age(member.dob, ctx.today)
```

### `person.is_minor(birth_date, reference_date, threshold?) -> bool`

Default threshold: 18.

```cel id="f767t8"
person.is_minor(member.dob, ctx.today)
```

### `person.sex_or_gender(value, system?) -> string`

Probably implemented as code mapping under the hood.

```cel id="1euag7"
person.sex_or_gender(source.sex, "odk.gender")
```

### `person.normalize_phone(value, country?) -> string`

Could be in `phone`, but person mappings use it often.

---

## 7.12 Phone and contact normalization

Namespace: `phone`.

### `phone.normalize(value, country?) -> string`

Returns E.164 where possible.

```cel id="zprj7n"
phone.normalize(source.phone, "KE")
```

### `phone.is_valid(value, country?) -> bool`

### `phone.country_code(value) -> string?`

### `phone.mask(value) -> string`

```cel id="pvbcl5"
phone.mask(source.phone)
```

---

## 7.13 Email

Namespace: `email`.

### `email.normalize(value) -> string`

### `email.is_valid(value) -> bool`

### `email.domain(value) -> string`

---

## 7.14 Geography

Namespace: `geo`.

For v0.1, keep this simple.

### `geo.point(lat, lon) -> map`

```cel id="5vuxr7"
geo.point(source.latitude, source.longitude)
```

Returns:

```json id="xif3nm"
{
  "type": "Point",
  "coordinates": [36.8219, -1.2921]
}
```

GeoJSON order is longitude, latitude.

### `geo.is_valid_lat(value) -> bool`

### `geo.is_valid_lon(value) -> bool`

### `geo.normalize_lat(value) -> double`

### `geo.normalize_lon(value) -> double`

### `geo.admin_code(value, system?) -> string`

Maps a location/admin code through code mapping.

```cel id="u5085s"
geo.admin_code(source.village_code, "odk.village")
```

---

## 7.15 Address

Namespace: `address`.

Keep this conservative.

### `address.line(values...) -> string`

```cel id="mzj170"
address.line(source.address1, source.address2)
```

### `address.normalize_country(value) -> string`

Returns ISO-3166 alpha-2 if possible.

```cel id="n5ehab"
address.normalize_country(source.country)
```

### `address.postal_code(value) -> string`

---

## 7.16 Validation and errors

Namespace: `validate`.

### `validate.required(value, message?) -> any`

Same as `require`, but clearer inside validation blocks.

```cel id="pzj81s"
validate.required(source.name, "name required")
```

### `validate.error(message, code?) -> never`

Always raises validation error.

```cel id="mwhs5q"
validate.error("unsupported gender")
```

### `validate.warn(condition, message, code?) -> bool`

Records warning if condition is false, but does not fail.

```cel id="qgx4i2"
validate.warn(source.age >= 0, "age is negative")
```

### `validate.matches(value, pattern, message?) -> bool`

### `validate.in(value, allowed_values, message?) -> bool`

```cel id="s5c2ln"
validate.in(source.status, ["active", "inactive"])
```

### `validate.range(value, min, max, message?) -> bool`

---

## 7.17 JSON helpers

Namespace: `json`.

### `json.parse(value) -> any`

Parses JSON string.

```cel id="9b8btt"
json.parse(source.raw_payload)
```

### `json.stringify(value) -> string`

### `json.path(value, path, fallback?) -> any`

Potentially useful if you use JSONPath-like paths.

```cel id="mip99n"
json.path(source, "$.person.name")
```

This is optional. `map.get` may be enough for v0.1.

---

## 7.18 Security and privacy helpers

Namespace: `privacy`.

These are useful if dealing with beneficiary/person data.

### `privacy.mask(value, visible_last?) -> string`

```cel id="s9k1ni"
privacy.mask(source.national_id, 4)
```

### `privacy.sha256(value, salt?) -> string`

```cel id="nbhqb2"
privacy.sha256(source.national_id, ctx.salt)
```

### `privacy.redact(value) -> string`

Always returns:

```text id="jj3c7i"
"[REDACTED]"
```

---

# 8. Recommended v0.1 Minimum Function Set

Do **not** implement everything first.

I would start with this list:

```text id="8ujb85"
present
missing
blank
coalesce
default
require
null_if_blank

type.string
type.int
type.float
type.bool
type.list
type.is_string
type.is_number
type.is_list
type.is_map

text.trim
text.lower
text.upper
text.title
text.normalize_space
text.replace
text.regex_replace
text.matches
text.split
text.join

date.parse
date.parse_datetime
date.format
date.age_on
date.is_valid

num.round
num.safe_divide

list.compact
list.unique
list.first
list.length

map.get
map.has
map.pick
map.merge

code.map
code.map_or_null
code.map_or_default
code.exists
code.label
code.canonical
code.normalize

id.make
id.uuid_v5
id.hash
id.clean

phone.normalize
phone.is_valid

email.normalize
email.is_valid

geo.point
geo.is_valid_lat
geo.is_valid_lon

validate.required
validate.error
validate.warn
validate.in
validate.range

json.parse
json.stringify

privacy.mask
privacy.sha256
privacy.redact
```

That is enough to build real mappings.

---

# 9. Error Model

Every expression evaluation should return either:

```rust id="gih71l"
Ok(Value)
```

or:

```rust id="zup5cx"
Err(MappingError)
```

## 9.1 Error shape

```json id="4c6lbx"
{
  "code": "TYPE_ERROR",
  "message": "Expected integer but got string",
  "path": "records.people.fields.age",
  "expression": "type.int(member.age)",
  "source_path": "members[0].age",
  "record": "people",
  "index": 0,
  "severity": "error"
}
```

## 9.2 Error codes

Recommended core codes:

```text id="dtxo86"
MISSING_REQUIRED_VALUE
TYPE_ERROR
PARSE_ERROR
INVALID_DATE
INVALID_NUMBER
INVALID_CODE
UNKNOWN_CODE_SYSTEM
UNKNOWN_FUNCTION
EVALUATION_ERROR
VALIDATION_ERROR
INTERNAL_ERROR
```

## 9.3 Error policy

At mapping level:

```yaml id="pngp5l"
errors:
  mode: strict
```

Supported modes:

| Mode      | Behavior                                                    |
| --------- | ----------------------------------------------------------- |
| `strict`  | First error fails mapping                                   |
| `collect` | Continue and collect all errors                             |
| `lenient` | Invalid optional fields follow `on_error`, errors become warnings |

Default should be:

```text id="c3zbht"
strict
```

All modes produce the same conceptual result shape:

```json id="8fbjnu"
{
  "records": {},
  "warnings": [],
  "errors": []
}
```

Mode details:

| Mode      | Error handling                                                                 |
| --------- | ------------------------------------------------------------------------------ |
| `strict`  | Stop at first error and return it in `errors`; do not emit the failing record   |
| `collect` | Continue evaluating independent records/fields and collect errors               |
| `lenient` | Convert non-required field errors to warnings and apply field `on_error` policy |

Partial output rules:

```text id="qbuxhb"
record-level emit/foreach/when error → do not emit that record instance
required field error → do not emit that record instance
optional field error + on_error null → emit field as null
optional field error + on_error omit → omit field
optional field error + on_error default → emit configured default
```

In `collect` mode, errors do not prevent other record instances from being emitted. In `strict` mode, evaluation stops immediately.

---

# 10. Rust API

This section describes the **reference implementation** in `crates/crosswalk-core` (names and signatures may drift slightly; see `cargo doc -p crosswalk-core`).

## 10.1 Core structs

```rust id="qgp7x0"
pub struct MappingRuntime {
    pub options: RuntimeOptions,
    pub limits: SecurityLimits,
    // + internal function registry and code-system registry
}

pub struct RuntimeOptions {
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub max_expression_cost: Option<u64>, // reserved (no engine hook in current `cel` crate)
    /// When mapping YAML omits `errors.mode`, this string (`strict` / `collect` / `lenient`) applies.
    pub default_errors_mode: Option<String>,
}

pub struct EvaluationInput {
    pub source: Value,
    pub context: Value,
}

pub struct MappingOutput {
    pub records: BTreeMap<String, Vec<Value>>,
    pub warnings: Vec<MappingError>,
    pub errors: Vec<MappingError>,
}
```

`errors.mode` in the mapping document overrides `RuntimeOptions::default_errors_mode` when present.

## 10.2 Main API

```rust id="dxppd4"
impl MappingRuntime {
    pub fn new(options: RuntimeOptions) -> Self;

    pub fn register_code_system(
        &mut self,
        name: &str,
        entries: HashMap<String, CodeEntry>,
    );

    pub fn compile_mapping(&self, yaml: &str) -> Result<CompiledMapping, CompileError>;

    pub fn evaluate(
        &self,
        mapping: &CompiledMapping,
        input: EvaluationInput,
    ) -> MappingOutput;

    /// Same bindings as a field expression (`source`, `ctx`, stdlib); no mapping YAML.
    pub fn evaluate_cel_expression(
        &self,
        expr: &str,
        input: EvaluationInput,
    ) -> Result<Value, StandaloneEvalError>;

    /// Editor-oriented: always returns structured preview (syntax, rewrite, optional value).
    pub fn preview_cel_expression(
        &self,
        expr: &str,
        input: EvaluationInput,
    ) -> ExpressionPreviewResult;
}
```

`compile_mapping` returns **`CompileError`** when YAML, functions, code systems, or CEL parse/type checks fail. **`evaluate`** returns **`MappingOutput`** (same JSON shape as WASM/Python) so callers can treat `errors.is_empty()` as success for mapping evaluation.

## 10.3 Compile expressions once

Compile CEL expressions once when loading the mapping.

Do not parse expressions for every record.

```rust id="3996ny"
let compiled = runtime.compile_mapping(mapping_yaml)?;
let output = runtime.evaluate(&compiled, input);
```

## 10.4 Standalone expressions and editor preview

For tooling and UIs that edit a **single CEL expression** (not a full mapping document):

- **`evaluate_cel_expression`** — `Result` on failure (parse, type, runtime).
- **`preview_cel_expression`** — always returns **`ExpressionPreviewResult`**: `author_expression`, optional `rewritten_expression`, optional evaluated `value`, `issues` (each with `phase`, `severity`, `message`, optional `line`/`column` in the **rewritten** buffer for syntax errors), and `notes` (stable hints for tools/LLMs; may be empty).

Serialization to JSON for bindings uses the same field names (`snake_case` in Rust, camelCase where a binding layer maps it).

---

# 11. JavaScript/WASM API

## 11.1 Build and package layout

The WASM crate is **`crates/crosswalk-wasm`**. A typical build writes into **`packages/js/wasm-pkg/`** (see root `README.md` and `packages/js` scripts).

The generated **`WasmMappingRuntime`** type is a thin wrapper: methods take and return **JSON strings** for portability across hosts.

## 11.2 WASM surface (current)

Illustrative usage from TypeScript/JavaScript (pseudo; exact imports depend on `wasm-pack` target):

```ts id="5gws7b"
import init, { WasmMappingRuntime } from "./wasm-pkg/crosswalk_wasm.js";

await init();

const rt = new WasmMappingRuntime();

rt.set_runtime_options_json(
  JSON.stringify({ default_errors_mode: "collect", timezone: "Asia/Bangkok" }),
);
rt.set_limits_json(JSON.stringify({ /* SecurityLimits fields */ }));

const meta = JSON.parse(rt.compile_mapping_meta(mappingYaml));
if ("error" in meta) throw new Error(meta.error);

const result = JSON.parse(
  rt.evaluate_json(mappingYaml, JSON.stringify(source), JSON.stringify(ctx)),
);
// result.records, result.warnings, result.errors

const probe = JSON.parse(
  rt.evaluate_expression_json("source.x + 1", JSON.stringify({ x: 1 }), "{}"),
);
// probe.ok === true → probe.value; probe.ok === false → probe.error (string)

const preview = JSON.parse(
  rt.preview_expression_json("1 + source.x", JSON.stringify({ x: 1 }), "{}"),
);
// preview.author_expression, preview.rewritten_expression?, preview.value?, preview.issues, preview.notes
```

Method names on **`WasmMappingRuntime`** follow the Rust `snake_case` exports from `wasm-bindgen` (e.g. `evaluate_json`, `preview_expression_json`).

## 11.3 JS result shape (full mapping)

```ts id="wmtq9e"
type MappingResult = {
  records: Record<string, unknown[]>;
  warnings: MappingIssue[];
  errors: MappingIssue[];
};
```

## 11.4 Standalone expression JSON (WASM)

- **`evaluate_expression_json(expr, source_json, ctx_json)`** — returns **`{"ok": true, "value": …}`** on success, or **`{"ok": false, "error": "…"}`** when `source_json` is not valid JSON or CEL compile/evaluate fails (message is the same `Display` as Rust `StandaloneEvalError`). Invalid **`ctx_json`** is treated like mapping evaluation: replaced with **`{}`**.
- **`preview_expression_json(expr, source_json, ctx_json)`** — always returns JSON matching Rust **`ExpressionPreviewResult`** (serde field names: `author_expression`, `rewritten_expression`, `value`, `issues`, `notes`). Invalid **`source_json`** becomes a single **`issues`** entry (phase **`evaluation`**, validation-style message); invalid **`ctx_json`** → **`{}`**.

The **`packages/js`** entry re-exports the wasm module, typed **`parseEvaluateExpressionJson`** / **`parsePreviewExpressionJson`**, and a higher-level **`Crosswalk`** class (camelCase, object in / parsed results out). See **`packages/js/README.md`** for usage examples.

---

# 12. Python API

## 12.1 Package

Published-style name (workspace crate **`crosswalk-python`**):

```text id="qtgap1"
crosswalk
```

## 12.2 Python usage

The extension uses **dict in/out** for evaluation where possible; JSON-string helpers remain for interop. Construct **`MappingRuntime`** with no args (defaults) or pass **`runtime_options`** as a dict or JSON string (`timezone`, `locale`, `max_expression_cost`, `default_errors_mode`).

```python id="dwcv7j"
from crosswalk import MappingRuntime, MappingCompileError, CompiledMapping

rt = MappingRuntime({"default_errors_mode": "collect", "timezone": "Asia/Bangkok"})

rt.register_code_system(
    "odk.gender",
    {
        "male": {"id": "canonical.gender.male", "label": {"en": "Male"}},
        "female": {"id": "canonical.gender.female", "label": {"en": "Female"}},
    },
)

try:
    compiled: CompiledMapping = rt.compile_mapping(mapping_yaml)
except MappingCompileError as e:
    raise

out = rt.evaluate_compiled(
    compiled,
    odk_submission,
    {"today": "2026-05-03", "timezone": "Asia/Bangkok"},
)

one_shot = rt.evaluate(mapping_yaml, odk_submission, {"today": "2026-05-03"})

value = rt.evaluate_expression("source.x + 1", {"x": 1}, {})

preview = rt.preview_expression("1 + source.x", {"x": 1}, {})
# preview["issues"], preview["notes"], preview.get("value"), author vs rewritten expr strings
```

`source` in CEL is the **first positional dict** (not nested under a `"source"` key in the Python API). Use **`preview_expression`** for editors; it does not raise on syntax errors—inspect **`issues`**.

---

# 13. Code System Registry

## 13.1 Basic code system format

The canonical internal schema for a code-system entry is an object:

```yaml id="p2n071"
code_systems:
  odk.gender:
    male:
      id: canonical.gender.male
      label:
        en: Male
    female:
      id: canonical.gender.female
      label:
        en: Female
    other:
      id: canonical.gender.other
      label:
        en: Other
```

Allowed shorthand:

```yaml id="k98apg"
code_systems:
  odk.gender:
    male: canonical.gender.male
```

The compiler must normalize shorthand to:

```yaml id="x3vpow"
code_systems:
  odk.gender:
    male:
      id: canonical.gender.male
```

before registering the code system.

## 13.2 Alias support

```yaml id="0qwi09"
code_systems:
  odk.gender:
    male:
      id: canonical.gender.male
      aliases:
        - m
        - man
        - masculine
```

Then:

```cel id="rm9vq8"
code.map("odk.gender", "M")
```

returns:

```text id="vjuwan"
canonical.gender.male
```

Alias and normalization rules:

```text id="n9xw83"
canonical key and alias lookups use code.normalize
canonical keys are included as implicit aliases
alias collisions within one code system are compile errors
duplicate canonical ids are allowed only when explicitly marked as aliases of the same concept
```

## 13.3 Mapping metadata

Support richer mappings later:

```yaml id="hbfxv2"
code_systems:
  odk.gender:
    female:
      id: canonical.gender.female
      confidence: exact
      source: odk
      target: canonical
      predicate: exactMatch
```

This leaves room for SKOS/SSSOM-style mappings later.

---

# 14. Determinism Rules

A mapping must produce the same output for the same input, mapping spec, code systems, and context.

Therefore:

```text id="7cn2zu"
No system clock inside functions
No random IDs
No HTTP calls
No filesystem access
No database calls
No locale guessing from host system
No timezone guessing from host system
```

Use explicit context:

```json id="k9k6zf"
{
  "ctx": {
    "today": "2026-05-03",
    "timezone": "Asia/Bangkok",
    "locale": "en"
  }
}
```

---

# 15. Security Rules

Expressions may be user-authored, so the runtime should enforce:

```text id="8zcsgs"
max expression size
max evaluation cost
max recursion depth if any
max output size
max list size
max string size
timeout / cancellation where available
function allowlist
no host I/O
no dynamic function registration from untrusted mappings
```

CEL’s non-Turing-complete, mutation-free design helps here, but the host still needs limits. ([GitHub][5])

---

# 16. Recommended Project Layout

```text id="re2er3"
crosswalk/
  crates/
    crosswalk-core/
      src/
        lib.rs
        value.rs
        runtime.rs
        mapping.rs
        errors.rs
        functions/
          mod.rs
          presence.rs
          text.rs
          date.rs
          number.rs
          list.rs
          map.rs
          code.rs
          id.rs
          validation.rs
    crosswalk-wasm/
      src/
        lib.rs
    crosswalk-python/
      src/
        lib.rs
  packages/
    js/
      package.json
      src/
        index.ts
  python/
    pyproject.toml
  examples/
    odk-household.yaml
    code-systems.yaml
```

---

# 17. Example End-to-End Mapping

```yaml id="5fs9m2"
version: 0.1
name: odk_household_to_canonical
source_system: odk
target_model: canonical.household_bundle

code_systems:
  odk.gender:
    male:
      id: canonical.gender.male
      label:
        en: Male
      aliases: ["m", "man"]
    female:
      id: canonical.gender.female
      label:
        en: Female
      aliases: ["f", "woman"]

records:
  households:
    emit: "present(source.__id)"
    fields:
      id: "id.make('household', source.__id)"
      external_id: "source.__id"
      village: "text.normalize_space(source.village)"
      submitted_at: "date.parse_datetime(source.__system.submissionDate)"

  people:
    foreach: "source.members"
    as: "member"
    when: "present(member.name)"
    fields:
      id: "id.make('person', source.__id, index)"
      household_id: "id.make('household', source.__id)"
      name: "text.title(text.normalize_space(member.name))"
      birth_date: "date.parse(member.dob, 'yyyy-MM-dd')"
      age: "date.age_on(member.dob, ctx.today)"
      gender: "code.map_or_default('odk.gender', member.sex, 'canonical.gender.unknown')"
      phone: "phone.normalize(member.phone, ctx.country)"
      is_minor: "date.age_on(member.dob, ctx.today) < 18"

validations:
  - expr: "present(source.__id)"
    message: "Submission ID is required"
  - expr: "source.members.size() > 0"
    message: "At least one household member is required"
```

---

# 18. v0.1 Build Plan

I would build it in this order:

```text id="fl7juq"
1. Rust Value model
2. Mapping YAML parser
3. CEL compile/evaluate wrapper
4. Minimal function registry
5. Code system registry
6. Record/foreach/field evaluator
7. Error collection
8. JS/WASM wrapper
9. Python wrapper
10. Golden test suite
```

The first real milestone should be:

```text id="io80ai"
Given one source JSON object and one mapping YAML,
produce canonical JSON records with errors/warnings.
```

---

# 19. Blunt Product Recommendation

Do **not** make the standard function library too clever at first.

The core product value is not having 300 functions. The value is:

```text id="2fj213"
stable mapping spec
safe CEL expressions
predictable function semantics
good errors
cross-language runtime
deterministic code/vocabulary mappings
```

For v0.1, implement the minimum set in section 8, write a strong test suite, and avoid anything that requires I/O, live lookups, or cultural assumptions.

[1]: https://cel.dev/?utm_source=chatgpt.com "Common Expression Language: CEL"
[2]: https://github.com/cel-rust/cel-rust?utm_source=chatgpt.com "cel-rust/cel-rust: Common Expression Language interpreter ..."
[3]: https://rustwasm.github.io/docs/wasm-bindgen/?utm_source=chatgpt.com "Introduction - The `wasm-bindgen` Guide"
[4]: https://pyo3.rs/?utm_source=chatgpt.com "Introduction - PyO3 user guide"
[5]: https://github.com/google/cel-spec?utm_source=chatgpt.com "google/cel-spec: Common Expression Language"
