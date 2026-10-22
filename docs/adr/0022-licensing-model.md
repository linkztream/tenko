# ADR 0022: Licensing model

- Status: Accepted
- Date: 2026-10-22

## Context

The placeholder `LICENSE` of the repository's first commit left the licence open between Apache-2.0 and AGPL-3.0 until a publication (API-20, a ROADMAP open question). The owner's intent, stated on 2026-10-22, has four parts: home users and companies may use and modify the software freely for their own internal use; embedding, packaging or selling it as part of a commercial product or a hosted service needs permission; whoever wants to commercialise it is referred to a separate royalty agreement with the owner; and contributions must be accepted without losing the right to sell the product commercially. The dependency graph holds no GPL, AGPL, MPL or OpenSSL crate (`deny.toml`), so no dependency constrains the choice; the npm packages of the web UI are checked separately before a publication.

## Decision

1. The software is licensed under the Business Source License 1.1 (`LICENSE.md`). Its Additional Use Grant allows production use, including modified versions, for Internal Use: running the software for the networks, systems and devices of one's own organization and its members, affiliates included, on premises or on rented infrastructure, and personal, household, educational and hobby use. A Commercial Offering (hosting the software as a service, embedding it in a product or appliance, reselling it, serving subscribers with it) is outside the grant and needs a commercial licence from the Licensor; consultants who deploy it on a customer's own infrastructure are inside the grant.
2. The Change License is AGPL-3.0-or-later and the Change Date is four years after each version's publication, as the BSL requires. With AGPL rather than Apache the converted versions stay unattractive for closed hosted or appliance forks while the Licensor can still sell proprietary licences for them, which keeps the dual-licensing position after the conversion.
3. Contributions are accepted under a contributor license agreement (`CLA.md`): contributors keep their copyright and grant an irrevocable, sublicensable licence with an explicit right to relicense commercially, a patent licence, representations and a moral-rights waiver to the extent Swedish law allows, under Swedish law; acceptance is recorded in the first pull request and every commit carries `Signed-off-by`. An entity version covers contributions made on an employer's behalf.
4. `README.md` explains under "Commercial Use & Royalties" when a royalty agreement is needed and when not; `CONTRIBUTING.md` carries the licensing and CLA section. The licensor is named in the licence with the contact address; the Cargo licence field is `BUSL-1.1`.
5. The texts are drafts for a lawyer's review before any publication (the BSL covenant on the Change License's GPL compatibility, the court of first instance and the moral-rights clause in particular); the repository stays private until then.

## Consequences

- Every file in a published release is covered by `LICENSE.md`; the deployment templates and documentation are part of the Licensed Work.
- Each version carries its own Change Date, so the release process must record the publication date per version (API-19's signed releases and SBOM are the place).
- `deny.toml` keeps the permissive allow list and excludes copyleft dependencies, since a copyleft dependency would bind the converted versions.
- External pull requests are merged only after the CLA acceptance is on record; the lead checks the sign-off line as part of the review.
- The licence of an already published version cannot be changed; a later decision applies to later versions only.

## Alternatives considered

- **Apache-2.0 as the Change License.** Rejected: once a version converts, nothing remains to sell for it.
- **Elastic License 2.0.** Rejected: it bars hosted services only, so an appliance vendor could bundle the software.
- **PolyForm Internal Use.** Rejected: it grants no redistribution, so no shared forks or packaging.
- **PolyForm Noncommercial.** Rejected: it forbids a company's own use, which the owner wants to allow.
- **PolyForm Shield and the Functional Source License.** Rejected: they bar only competing products, which is narrower than the owner's bar.
- **Copyright assignment instead of a CLA licence grant.** Rejected: cleaner standing to sue over a contributed part alone, but partly ineffective under Swedish moral rights and a deterrent for contributors.
