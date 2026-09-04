---
paths:
  - "**/*.rs"
---

# Rust conventions

Opinions and gotchas only. Naming, import order, `match` exhaustiveness,
`?` over manual propagation and the rest of the basics are enforced by
`rustc`, `rustfmt` and `clippy`, so they are not repeated here. Most of
these rules come from
[Canonical's Rust Best Practices](https://canonical.github.io/rust-best-practices/).

## Blank lines carry meaning

Use blank lines semantically, not aesthetically. They delimit strongly
associated sections, consistently, regardless of section size.

* A variable declared and used only by the block that follows it belongs to
  that block: no blank line between them.
* A variable used by several later blocks is not tied to the one right
  after it: put a blank line.
* A declaration and the check that guards it stay together. Once the check
  runs past about three lines the pair is its own block, so put a blank
  line after it.

## Don't interleave unrelated code

Interleaving looks deliberate to a new reader, who then hunts for a
relationship that isn't there. Group strongly interdependent sections.

This bites hardest with closures. A closure bound halfway through a
function, capturing nothing and used only at the end, makes the reader
carry it the whole way. If it captures, declare it next to its use. If it
doesn't, make it an `fn`. Often it shouldn't be a closure at all: a
top-to-bottom flow reads better than a helper closure.

## Shortest clause first

In conditionals and match arms put the shorter clause first:
`if condition.is_none() { short } else { long }` over
`if let Some(value) = condition { long } else { short }`.

Skip it when satisfying it would need an empty block or a filler comment.

## Dead code

`#[allow(dead_code)]` always carries a comment explaining why the code is
kept rather than deleted.

## SQL

* `sqlx::query!` and `sqlx::query_as!` validate against the schema at
  compile time. Parameterize with `$1`, `$2`, ...; never interpolate.
* Multi-table writes that must stay consistent go in one transaction.
* Map database errors to HTTP status codes and log the underlying detail.
