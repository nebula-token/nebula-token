# Versioning

NEBULA carries two version numbers that move at very different speeds. Confusing
them is the most likely way to misread a release, so they are defined separately
here.

---

## 1. The specification version

`spec_version` identifies the wire format and the behaviour. It is an integer,
currently **1**, and it appears in three places that must always agree:

- `SPECIFICATION.md` (title and header)
- `spec/test-vectors.json` and `spec/behavior-vectors.json` (`spec_version` key)
- every package, as an exported constant (`SPEC_VERSION`) — required by [N-4]

A change to `spec_version` means a new token prefix and a new set of vectors
([N-51]). Tokens of two spec versions can coexist on one endpoint because the
prefix distinguishes them before any database interaction.

**We do not expect a version 2.** The design contains no cryptographic agility
and nothing that ages: no public-key algorithm to migrate, no negotiated
parameters, no extension points to grow into. If version 2 ever exists it will be
because the model itself changed, not because an algorithm did.

### Errata

A defect in the specification text that does not change conforming behaviour —
an internal contradiction, an ambiguity, a missing vector for a rule that every
implementation already follows — is published as an erratum in
`spec/ERRATA.md` and, where relevant, as an added vector. Errata never change
`spec_version`. They are announced in the changelog like any other change.

## 2. Package versions

Each package follows [Semantic Versioning 2.0.0](https://semver.org/) against
its own public API, as delimited by [`COMPATIBILITY.md`](COMPATIBILITY.md).

**All ten packages share the same MAJOR.MINOR.** They are one artefact published
ten ways; a behavioural change lands everywhere or nowhere, and a user comparing
two languages must not have to reason about which of them received a feature.

**PATCH may differ per package.** A crash that only affects Ruby is fixed by
publishing a Ruby patch. Forcing nine other releases would add nine unreviewed
diffs for no benefit.

So `1.2.x` means the same behaviour in every language, and `nebula-token` 1.2.3
for Python and 1.2.0 for Go are the same NEBULA.

### What each level means

| Bump | Trigger |
|---|---|
| MAJOR | A change to a surface frozen in COMPATIBILITY.md §2, or a new `spec_version` |
| MINOR | A new capability; a new error code; a new supported runtime; dropping an end-of-life runtime; a deprecation |
| PATCH | A bug fix, a documentation fix, or a dependency bump with no API effect |

A security fix takes the smallest bump that carries it, and is backported to the
supported line per [`SECURITY.md`](SECURITY.md).

## 3. Which spec version a package implements

Every package exports `SPEC_VERSION` and states it in its README. A package's
own version tells you nothing about the spec version, deliberately: package 1.4.0
and package 2.0.0 may both implement spec version 1, because a major bump can be
forced by an API ergonomics change that leaves the wire format untouched.

To check compatibility between two deployments, compare `SPEC_VERSION`. To check
whether an upgrade will break your build, compare package majors.

## 4. Pre-1.0 and pre-release identifiers

There are none in the 1.x line. Release candidates, if used, take the form
`1.3.0-rc.1` and are published to each registry's pre-release channel where one
exists. They are never the default install.

Six of the ten registries give that for free — PyPI, crates.io, NuGet, RubyGems,
Hex and pub.dev all exclude a prerelease from default resolution. npm does not:
`npm publish` moves the `latest` dist-tag whatever the version says, so
`release.yml` publishes any version containing a `-` to the `next` tag instead.
Maven Central and Packagist have no prerelease channel at all; there, an `-rc`
version is an ordinary version that resolvers rank below the release, and Go's
proxy applies the same SemVer rule. See [`RELEASING.md`](RELEASING.md), "Cutting
a release candidate".

## 5. Go is versioned differently, of necessity

The Go module is `github.com/nebula-token/nebula-token/packages/go` — a
**submodule** living in a subdirectory of this repository. Go resolves versions
from repository tags, not from a manifest, and for a submodule the only tags it
will look at are the ones prefixed with the module's directory:

```
packages/go/v1.0.0      ← the version of the Go module
v1.0.0                  ← the version of everything else; invisible to Go
```

Both tags are pushed by the same release ([`RELEASING.md`](RELEASING.md)), so
`packages/go/v1.2.3` and `v1.2.3` describe the same commit and the MAJOR.MINOR
rule of §2 still holds. But they are different names for Go's purposes: a bare
`v1.2.3` tag is not a version of this module, and tagging only that one
publishes nothing to `proxy.golang.org`.

There is no vanity import path. The module used to declare
`go.nebulatoken.dev/nebula-token`, which required the `go.mod` to sit at a
repository root and a `go-import` meta tag to be served, correctly, forever:
every `go get` in every consumer's CI depended on one DNS name and one HTML
response staying alive. Dropping it removes that dependency outright — the
module now resolves the same way the rest of GitHub does — at the cost of an
import path that names the directory. That trade is documented in
[`RELEASING.md`](RELEASING.md).

Go's import-path-versioning rule means a Go major bump changes the import path:
`module github.com/nebula-token/nebula-token/packages/go/v2`, tagged
`packages/go/v2.0.0`. This is one more reason a major bump is treated as a
serious event rather than a routine one.

## 6. Reading a version at a glance

```
nebula-token 1.2.3, spec version 1
             │ │ │              └─ wire format and behaviour: interoperates with
             │ │ │                 every other implementation of spec version 1
             │ │ └─ patch: fixes only, may differ between languages
             │ └─ minor: same across all ten languages, additive only
             └─ major: an API surface in COMPATIBILITY.md §2 changed
```
