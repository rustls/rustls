# Contributing

Thanks for considering helping this project.  There are many
ways you can help: using the library and reporting bugs,
reporting usability issues, making additions and improvements
to the library, documentation and finding security bugs.

## Reporting bugs

Please file a github issue.  Include as much information as
possible.  Suspected protocol bugs are easier debugged with
a pcap or reproduction steps.

Feel free to file github issues to get help, or ask a question.

If you believe you've found a security bug please
[open a draft security advisory](https://github.com/rustls/rustls/security/advisories/new)
in GitHub, and not as a regular repository issue. See [SECURITY.md] for more
information.

## Code changes

Some ideas and guidelines for contributions:

- For large features, file an issue prior to starting work.
  This means everyone can see what is in progress prior to a PR.
- Feel free to submit a PR even if the work is not totally finished,
  for feedback or to hand-over.
- Prefer not to reference github issue or PR numbers in commits.
- Try to keep code formatting commits separate from functional commits.
- See [`.github/workflows/build.yml`](.github/workflows/build.yml) for
  how to run the various test suites, and how to make coverage measurements.
- I run `cargo outdated` prior to major releases; but PRs to update specific
  dependencies are welcome.

## Commit history

We prefer to keep the commit history clean and easy to follow. As such, we prefer small commits
that do one thing. In particular:

* Avoid mixing refactoring and functional changes in the same commit if possible
* Make mechanical changes (like renaming or moving code around) in a separate commit
* Isolate updates to `Cargo.lock` in their own commits

Our default workflow is to rebase clean commit history from a PR to `main`.

## Security bugs

Please report security bugs by [opening a draft security advisory](https://github.com/rustls/rustls/security/advisories/new)
in GitHub, and not as a regular repository issue.

See [SECURITY.md] for more information.

If you're *looking* for security bugs, this crate is set up for
`cargo fuzz` but would benefit from more runtime, targets and corpora.

## Testing

- Features involving additions to the public API should have (at least)
  API-level tests (see [`rustls/tests/api.rs`](rustls/tests/api.rs)).
- Protocol additions should have some coverage -- consider enabling
  corresponding tests in the bogo suite, or writing some ad hoc tests.

PRs which cause test failures or a significant coverage decrease
are unlikely to be accepted.

### Testing with multiple `CryptoProvider`s

Generally any test that relies on a `CryptoProvider` anywhere, should
be run against all `CryptoProvider`s, such that
`cargo test --all-features` runs the test several times.  To achieve that
we have two methods:

- For unit tests, see `rustls/src/test_macros.rs` which provides the
  `test_for_each_provider!` macro.  This can be placed around normal
  tests and instantiates the tests once per provider.

  Note that rustfmt does not format code inside a macro invocation:
  when developing test code, sed `test_for_each_provider! {` to `mod tests {`,
  format the code, then sed it back.

- For integration tests -- where the amount of test code is more significant,
  and lack of rustfmt support is more painful -- we instantiate the tests
  by importing them multiple times, and then the tests resolve the provider
  module to use via `super::provider`.
  For example, see `rustls/tests/runners/unbuffered.rs` and
  `rustls/tests/unbuffered.rs`.

## Style guide

### Ordering

#### Top-down ordering within modules

Within a module, we prefer to order items top-down. This means that items within
a module will depend on items defined below them, but not (usually) above them.
The idea here is that the public API, with more internal dependencies, will be
read (and changed) more often, and putting it closer to the top of the module
makes it more accessible.

This can be surprising to many engineers who are used to the bottom-up ordering
used in languages like Python, where items can have a run-time dependency on
other items defined in the same module.

Usually `const` values will thus go on the bottom of the module (least complex,
usually no dependencies of their own), although in larger modules it can make
sense to place a `const` directly below the user (especially if there is a
single user, or just a few co-located users).

The `#[cfg(test)] mod tests {}` module goes on the very bottom, if present.

#### Ordering for a given type

For a given type, we prefer to order items as follows:

1. The type definition (`struct` or `enum`)
2. The inherent `impl` block (that is, not a trait implementation)
3. `impl` blocks for traits, from most specific to least specific.
   The least specific would be something like a `Debug` or `Clone` impl.

#### Ordering associated functions within an inherent `impl` block

Here's a guide to how we like to order associated functions:

0. Associated functions (that is, `fn foo() {}` instead of `fn foo(&self) {}`)
1. Constructors, starting with the constructor that takes the least arguments
2. Public API that takes a `&mut self`
3. Public API that takes a `&self`
4. Private API that takes a `&mut self`
5. Private API that takes a `&self`
6. `const` values

Note that we usually also practice top-down ordering here; where these are in
conflict, make a choice that you think makes sense. For getters and setters, the
order should typically mirror the order of the fields in the type definition.

### Functions

#### Consider avoiding short single-use functions

While single-use functions can make sense if the algorithm is sufficiently complex
that it warrants an explicit name and interface, using many short single-use
functions can make the code harder to follow, due to having to jump around in order
to gain an understanding of what's going on. When writing a single-use function,
consider whether it needs the dedicated interface, or if it could be inlined into
its caller instead.

#### Consider avoiding free-standing functions

If a function's semantics or implementation are strongly dependent on one of its
arguments, and the argument is defined in a type within the current crate,
prefer using a method on the type. Similarly, if a function is taking multiple
arguments that originate from the same common type in all call-sites it is
a strong candidate for becoming a method on the type.

#### Order arguments from most specific to least specific

When writing a function, we prefer to order arguments from most specific to
least specific. This means that an `image_id` might go before the `domain`,
which will go before the `app` context. More specific arguments are more
differentiating between a given function and other functions, so putting them
first makes it easier to infer the context/meaning of the function (compared to
starting with a number of generic context-like types).

#### Use `impl` where possible

We prefer to use `impl ...` for arguments and return types when there's a single
use of the type. Generic type argument bounds add a level of indirection that's
harder to read in one pass.

#### Avoid type elision for fully qualified function calls

We prefer to write [fully qualified function calls] with types included, rather
than elided. For example:

```rust
// Incorrect:
<_>::default()

// Correct:
CertificateChain::default()
```

[fully qualified function calls]: https://doc.rust-lang.org/beta/reference/expressions/call-expr.html#disambiguating-function-calls

#### Validation

Where possible, avoid writing `validate` or `check` type functions that try to
check for error conditions based on the state of a populated object. Prefer
["parse, don't validate"](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/)
style and try to use the type system to make it impossible for invalid states to
be represented.

#### Error handling

We use `Result` types pervasively throughout the code to signal error cases.
Outside of unit/integration tests we prefer to avoid `unwrap()` and `expect()`
calls unless there is a clear invariant which can be locally validated by the
structure of the code. If there is such an invariant, we usually add a comment
explaining how the invariant is upheld. In other cases (especially for error
cases which can arise from network traffic, which could represent an attacker),
we always prefer to handle errors and ultimately return an error to the network
peer or close the connection.

### Expressions

#### Avoid single-use bindings

We generally make full use of the expression-oriented nature of Rust. For
example, when using iterators we prefer to use `map` and other combinators
instead of `for`-loops when possible, and will often avoid variable bindings if
a variable is only used once. Naming variables takes cognitive efforts, and so
does tracking references to bindings in your mind. One metric we like to
minimize is the number of mutable bindings in a given scope.

Remember that the overall goal is to make the code easy to understand.
Combinators can help with this by eliding boilerplate (like replacing a
`None => None` arm with a `map()` call), but they can also make it harder to
understand the code. One example is that a combinator chain like
`.map().map_err()` might be harder to understand than a `match` statement
(since, in this case, both of the arms have a significant transformation).

#### Use early `return` and `continue` to reduce nesting

The typed nature of Rust can cause some code to end up at deeply indented
levels, which we call "rightward drift". This makes lines shorter, making the
code harder to read. To avoid this, try to `return` early for error cases, or
`continue` early in a loop to skip an iteration.

#### Hoist common expression returns

When writing a `match` or `if` expression that has arms that each share a return
type (e.g. `Ok(...)`), hoist the commonality outside the `match`. This helps
separate out the important differences and reduces code duplication.

```rust
// Incorrect:
match foo {
    1..10 => Ok(do_one_thing()),
    _ => Ok(do_another()),
}

// Correct:
Ok(match foo {
    1..10 => do_one_thing(),
    _ => do_another(),
})
```

#### Avoid `ref` in match patterns

When writing match expressions, try to avoid using `ref` in patterns. Prefer
taking a reference on the
[scrutinee](https://doc.rust-lang.org/reference/expressions/match-expr.html)
of the `match`.

Since the addition of [binding
modes](https://rust-lang.github.io/rfcs/2005-match-ergonomics.html) for improved
match ergonomics the `ref` keyword is unidiomatic and can be unfamiliar to
readers.

### Naming

#### Use concise names

We prefer concise names, especially for local variables, but prefer to
expand acronyms/abbreviations that are not very well known (e.g. prefer
`key_usage` instead of `ku`, `anonymous` instead of `anon`). Extremely common
short-forms like `url` are acceptable.

Avoid adding a suffix for a variable that describes its type (provided that its
type is hard to confuse with other types -- for example, we do still use `_id`
suffixes because we usually use numeric IDs for database entities). The
precision/conciseness trade-off for variable names also depends on the scope of
the binding.

#### Avoid `get_` prefixes

Per the
[API guidelines](https://rust-lang.github.io/api-guidelines/naming.html#getter-names-follow-rust-convention-c-getter),
`get_()` prefixes are discouraged.

#### Enum variants

When implementing or modifying an `enum` type, list its variants in alphabetical
order. It's acceptable to ignore this advice when matching the order imposed by
an external source, e.g. a standards document.

Prefer active verbs for variant names. E.g. `Allow` instead of `Allowed`,
`Forbid` instead of `Forbidden`. Avoid faux-bools like `Yes` and `No`, instead
preferring variant names that are descriptive of the different states.

#### Don't elide generic lifetimes

We prefer not to elide lifetimes when naming types that are generic over
lifetimes. Always include a lifetime placeholder (e.g. `<'_>`) to avoid
confusion.

### Imports

We use 3 blocks of imports in our Rust files:

1. `std` imports
2. Imports from external crates
3. Crate-internal imports

We believe that this makes it easier to see where a particular import comes from.

Within the import blocks we prefer to separate imports that don't share a parent
module. For example,

```rust
// Incorrect
use alloc::{format, vec::Vec};

// Correct
use alloc::format;
use alloc::vec::Vec;
```

We prefer to reference types and traits by an imported symbol name instead of
using qualified references. Qualification paths generally add noise and are
unnecessary. The one exception to this is when the symbol name is overly
generic, or easily confused between different crates. In this case we prefer to
import the symbol name under an alias, or if the parent module name is short,
using a one-level qualified path. E.g. for a crate with a local `Error` type,
prefer to `import std::error::Error as StdError`.

### Exports

We prefer to export types under a single name, avoiding re-exporting types from
the top-level `lib.rs`. The exception to this are "paved path" exports that we
expect every user will need. The canonical example of such types are
`client::ClientConfig` and `server::ServerConfig`. In general this sort of type
is rare and most new types should be exported only from the module in which they
are defined.

### Misc

#### Numeric literals

Prefer a numeric base that fits with the domain of the value being used. E.g.
use hexadecimal for protocol message literals, and octal for UNIX privileges.
Use digit grouping to make larger numeric constants easy to read, e.g. use
`100_000_000` instead of `100000000`.

#### Avoid type aliases

We prefer to avoid type aliases as they obfuscate the underlying type and
don't provide additional type safety. Using the
[newtype idiom](https://doc.rust-lang.org/rust-by-example/generics/new_types.html)
is one alternative when an abstraction boundary is worth the added complexity.

## Licensing

Contributions are made under [rustls's licenses](LICENSE).
