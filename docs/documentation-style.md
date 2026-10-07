# Documentation and communication style

Use approximately 80% ASD-STE100 style in x0x ADRs, other documentation, and
communication with David. David confirmed this writing target in D198. Do not claim
formal ASD-STE100 compliance or invent a compliance percentage.

## Write for people and machines

- Use short sentences. Aim for one main action or claim in each sentence.
- Use common words and the active voice. Name the actor when it matters.
- Use one term for one thing. Keep API names and necessary technical terms.
- Explain an unfamiliar term at first use. Do not simplify away a security,
  protocol or data-integrity distinction.
- State the result first. Then give the reason, evidence and next action.
- Keep each paragraph on one topic. Use lists for steps or parallel items.
- Use direct instructions, such as "Save the event before you send the receipt."
- State conditions, limits and failure results. Avoid vague claims such as
  "fully secure", "seamless", or "guaranteed" without an exact contract.
- Separate current behavior, agreed direction, Proposed work and release proof.
- Use `must` for a requirement, `should` for a recommendation with a stated
  exception, and `may` for permission. Keep existing normative meanings intact.

## Review an ADR

Keep the context, decision, alternatives, consequences and validation clear.
Put detailed wire layouts and full state machines in linked specifications.
The short ADR must still state the guarantees that those specifications obey.

Example:

> The adapter saves the event before it acknowledges acceptance. If it stops
> before that write completes, x0xd delivers the event again after restart.

Check that a reader can identify who acts, what they do, when they do it, and
what happens on failure. Review meaning and clarity; do not count approved
dictionary words to manufacture an 80% score.

## Apply the rule without changing history

Use this style for new and changed text. Improve editable old prose when that
work is in scope. Preserve accepted ADRs, frozen evidence, exact quotations,
protocol identifiers and retained historical reports. Do not rewrite immutable
records only to meet the style target. Use a proposed successor revision.

The same style applies to agent updates, review notes, PR descriptions and
answers to David. Retain technical detail needed to make a decision.
