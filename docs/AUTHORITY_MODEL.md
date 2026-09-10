# AUTHORITY_MODEL.md

The formal content of "this argument may determine what happens".

---

## 1. Elements

| Symbol | Element | Meaning |
| --- | --- | --- |
| `S` | Source | A declared origin of data. Carries an integrity tier, a sensitivity tier, and a set of operand kinds it is authoritative for. |
| `K` | Operand kind | A class of authority-bearing value: `email`, `url`, `posix_path`, `iban`, … |
| `v` | Operand | A concrete value of some kind, observed from one or more sources. |
| `O` | Origin | One recorded contribution: `(source, trust, sensitivity, step, path)`. |
| `T` | Tool | Something the agent can invoke. |
| `p` | Parameter | One argument of a tool, with a role and an optional kind set. |
| `Σ` | Session | The linear execution of one agent: ledger, observations, decisions. |

Note what is **absent**: there is no `Agent`, no `Principal` object, no
delegation chain, no token. IDENSEC does not model identity. Identity is a
different and well-served layer, and conflating the two is what makes agent
authorization look solved when it is not (see [ADR-0001](DESIGN_DECISIONS.md)).

---

## 2. The integrity lattice

Total order, lowest to highest:

```
TOOL_DESCRIPTION  <  TOOL_UNTRUSTED  <  TOOL_TRUSTED  <  USER_INPUT  <  SYSTEM
```

Matching the five tiers used in the 2026 agent information-flow literature, so
labels are comparable with published work.

`TOOL_DESCRIPTION` sits at the **bottom**, below untrusted tool output, and this
is the one placement that surprises people. Tool names, descriptions and schemas
*look* like configuration — they arrive at startup, they are written by
developers, they sit in a manifest. In MCP they are supplied by the server,
which makes them attacker-controllable at runtime. Anything that reads like
trusted configuration but crosses a trust boundary belongs here.

A source at `USER_INPUT` or above is a **principal source**: it speaks for the
human or the operator, and is authoritative for every kind without enumeration.
The principal is allowed to name their own destinations.

---

## 3. Source authority

Trust tier alone is not enough. A corporate directory is trustworthy, but it is
trustworthy *about people* — it has no business choosing a URL to fetch or a
path to delete. Authority is therefore declared per kind:

```python
Source("directory", Trust.TOOL_TRUSTED, authoritative_for={"email"})
```

Formally, for a source `S` and kind `k`:

```
authoritative(S, k)  ⟺  trust(S) ≥ USER_INPUT  ∨  k ∈ authoritative_for(S)
```

This is the mechanism that makes retrieve-then-act work without opening the door
to injection. The directory can supply a recipient. The web page cannot — not
because the web page is "suspicious", but because nobody said it could name
people.

---

## 4. Attribution

`attribute(x)` maps an argument value to a set of origins and a state.

```
attribute(x) = (ATTRIBUTED, origins)   if x is derivable from observed data
             = (UNATTRIBUTED, ∅)       otherwise
```

Derivation is deliberately narrow, deterministic, and free of semantics. The
permitted derivations are exactly:

| Derivation | Rule |
| --- | --- |
| `seal` | `x` is the value a handle resolves to. Provenance exact. |
| `operand` | `normalise(x)` equals a recorded operand of the same kind. |
| `trusted-substring` | `x` is a whole-token quotation of text from a principal source. |
| `untrusted-substring` | `x` is a whole-token quotation of text from a non-principal source. |

**Whole-token** is load-bearing. Plain substring matching allows a value to be
carved out of the middle of a longer trusted token: with the instruction
`Pay invoice 100234 for 50`, an amount of `1002` is a substring of `100234` and
would inherit the principal's authority. Matches must be delimited on both sides
by characters outside the identifier alphabet. This was a real bypass, found by
attacking the implementation; the regression test is in `tests/test_ledger.py`.

---

## 5. The admission rule

For a call `T(p₁ = x₁, …, pₙ = xₙ)`:

```
admit(T, x⃗)  ⟺  ∀ pᵢ with role(pᵢ) = AUTHORITY :
                     ∃ O ∈ origins(attribute(xᵢ)) . authoritative(source(O), kind(xᵢ))
                 ∧  ¬ egress_violation(T, x⃗)
```

Three consequences worth stating explicitly, because each is a design decision
that could plausibly have gone the other way:

**The quantifier over origins is existential** (ADR-0008). If the principal
wrote a value, that origin authorises it regardless of who else echoed it.
Universal quantification would hand an attacker a free denial-of-service: mention
the user's own address in a page the agent fetches, and the legitimate flow dies.
The attacker gains nothing from the existential rule, because they cannot cause a
*new* value to appear in the principal's own instruction.

**Sensitivity uses the opposite quantifier.** Confidentiality takes the maximum
over contributing origins: touching one confidential source taints the result
regardless of what else contributed. Integrity is existential-permissive;
confidentiality is universal-restrictive. Getting these the same way round is a
classic information-flow bug, and both directions are tested.

**`UNATTRIBUTED` is denied, not allowed** (ADR-0007). Safety is defined as
*positively derivable from an authorised source* — an allowlist — rather than
*does not match a known-bad value* — a blocklist. This is the difference between
a control and a filter.

---

## 6. Roles

Role is a property of the **tool interface**, not of the call (ADR-0004).
`to` in `send_email(to, subject, body)` bears authority in every invocation that
will ever exist. Re-deriving that per call is what costs the utility.

| Role | Determines | Untrusted data permitted |
| --- | --- | --- |
| `AUTHORITY` | What the action does to the world | No |
| `PAYLOAD` | What the action says | Yes — this is the point |
| `ADVISORY` | Presentation and non-security behaviour | Yes |

The split is what allows *summarise this page and mail it to my colleague*: the
summary is untrusted and flows into `body`; the recipient is authoritative and
fills `to`. An invocation-granularity monitor cannot express this, which is the
granularity mismatch the design exists to fix.

---

## 7. Effects

Sets, not tiers — a tool can be several at once.

```
READ · WRITE · DELETE · EXECUTE · NETWORK_EGRESS · FINANCIAL · IRREVERSIBLE
```

`NETWORK_EGRESS` is the one with teeth: it marks the sink where data leaves the
trust boundary, and it is what the confidentiality rules key on. Effects are
never inferred from a schema — see [`ARCHITECTURE.md`](ARCHITECTURE.md) §6.

---

## 8. What the model does *not* express

Stated so that nobody reads a guarantee into it:

- **Intent.** Provenance answers *who wrote this value*, not *what they meant by
  it*. An address the principal named in order to forbid it is still an address
  the principal named. See [`LIMITATIONS.md`](LIMITATIONS.md).
- **Aggregate consequence, unless you state a budget.** The admission rule above
  judges one call. Session budgets (`idensec.budget`) add the missing dimension —
  call counts, sums over a numeric parameter, distinct destinations touched —
  but they must be written down. IDENSEC cannot infer that "under 50,000" was a
  limit rather than a preference, because that is intent.
- **Correctness.** An authorised destination can still be the wrong one.
- **Identity.** Deliberately. See §1.
