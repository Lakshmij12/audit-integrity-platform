# AI Usage Log

Records which AI tools were involved, what each contributed, what material each received, and what the
candidate decided. AI recommendations and candidate decisions are recorded separately. This log is the
traceability record; commits do not carry AI co-author trailers.

## 1. Tools
| Tool | Role | Period |
|------|------|--------|
| Claude Code (Anthropic), VS Code extension, model Claude Opus 5.5 | Repository work: inspection, planning and design documents, and in later milestones implementation and tests. Every file change, install and commit is approved by the candidate first. | 2026-10-28 onward |
| OpenAI ChatGPT | Advisory: requirement interpretation, planning advice, prompt drafting and review of Claude Code's output. ChatGPT provided planning and review guidance; no repository implementation or testing is attributed to ChatGPT. | October 2026, including 2026-10-28 |

## 2. Contributions

### Claude Code
- Inspected the repository, Git configuration and GitHub visibility with read-only commands.
- Produced the requirements mapping, architecture, hash-chain/redaction/retention/export design, risk
  analysis, test strategy and milestone plan (plans v1 to v3.1).
- Ran dependency-resolution dry-runs for CPython 3.14 on Windows and Linux (no packages installed).
- Drafted the Step 0 verification commands and checked their output.
- Wrote and staged the commit 1 files and created commit 1 after candidate approval.
- Drafted the commit 2 documents (this file, REQUIREMENTS.md, DESIGN.md, LIMITATIONS.md) and created
  commit 2 after candidate approval.
- Wrote the redaction proof of concept (`poc/redaction_poc.py`), ran it with Python 3.14.3, and
  generated `docs/poc/redaction-poc-output.md` from the captured output.

### ChatGPT (as reported by the candidate)
- Helped interpret and organize the assessment requirements.
- Suggested a technology stack and a phased implementation approach.
- Prepared generic prompts that the candidate used with Claude Code.
- Reviewed Claude Code's architecture and implementation plans.
- Identified concerns involving cryptographic verification, redaction, archive integrity, export
  completeness, confidentiality, GitHub repository visibility and accurate AI-use documentation.
- Reviewed the proposed first commit and recommended keeping the attestation template blank.

ChatGPT's suggestions were advisory and reviewed by the candidate.

## 3. Material shared
| Tool | Material |
|------|----------|
| Claude Code | Assignment brief (PDF); screenshot of the recruiter's instruction email; candidate prompts; terminal output from the Step 0 authentication and identity checks |
| ChatGPT | Assignment brief (PDF) and recruiter instructions/screenshots during earlier discussions; Claude Code's architecture plans, design proposals, documentation drafts, code snippets and implementation updates |

External services contacted by Claude Code's own commands on 2026-10-28: PyPI (package names, via
`pip install --dry-run`) and the GitHub API (this repository's path, via `gh` and one anonymous request).
Claude Code cannot observe what was shared with other tools; the ChatGPT entries are as reported by the
candidate.

## 4. Session log
| # | Date | Activity | AI recommendation | Candidate decision |
|---|------|----------|-------------------|--------------------|
| 1 | 2026-10-28 | Repository inspection; plan v1 before the brief was shared with Claude Code | Claude Code: plan with assumed Scenario A/B/C mappings; asked for the scenario text | Superseded once the brief was shared |
| 2 | 2026-10-28 | Plan v2, from an early prompt that framed the work as an independent portfolio project; this framing was corrected when the actual assignment requirements were reviewed | Claude Code: broad plan including AWS, Docker, metrics and CI | Framing corrected to the assignment; scope cut to the three scenarios and the 2–3 day budget |
| 3 | 2026-10-28 | Brief and recruiter email shared with Claude Code; plan aligned to the brief | Claude Code: requirements mapping and design; flagged that the recruiter email ("make it public") conflicts with the brief (private repository); asked the candidate to confirm identity | Repository kept private |
| 4 | 2026-10-28 | Plan v3 | Claude Code: hash layout, invariants, guarantee levels, redaction PoC design, milestones | Direction approved subject to 12 refinements: focus on the scenarios; one Python version after a compatibility check; SHA-256 chain with documented genesis; PoC before redaction; separate guarantee levels; export completeness; retention evidence; reproducible tamper test; genuine history; confidentiality; accurate AI log; no invented results |
| 5 | 2026-10-28 | Plan v3.1 | Claude Code: revised design text and Milestone 1 file contents | 9 corrections: archive metadata vs content integrity; redaction authentication; accurate AI log; plaintext-storage limitation; validate installation; privacy; identity verification; assignment field names; no fabrication |
| 6 | 2026-10-28 | Milestone 1 review | Claude Code: proposed a Co-Authored-By trailer and a pip-freeze lock file | 10 adjustments: nothing marked approved without explicit approval; attestation as a template; verify the repository before the first commit; record ChatGPT and Claude Code; no Co-Authored-By trailer; lock generated from declared dependencies; document plaintext archives and propose an improvement; tamper demo must not rely on triggers; show status and staged diff before each commit; no install, commit, push or visibility change without approval |
| 7 | 2026-10-28 | Step 0 verification | Claude Code: verification commands; read-only checks | Candidate logged `gh` into the repository owner account, set a repository-local Git identity and confirmed the commit email is verified. Results: owner `Lakshmij12`, visibility `PRIVATE`, anonymous access 404 |
| 8 | 2026-10-28 | Commit 1 (`2641783`) | Claude Code: .gitignore additions, attestation template, commit message | Approved as proposed; attestation details left blank for the candidate to complete |
| 9 | 2026-10-28 | Commit 2 (`03e2d98`) | Claude Code: drafted the four documentation files | Candidate specified the ChatGPT entries and content requirements, requested five edits, then approved; committed as `03e2d98` |
| 10 | 2026-10-28 | Commit 3 prepared: redaction proof of concept | Claude Code: wrote `poc/redaction_poc.py` (14 self-checks, synthetic data), ran it with Python 3.14.3 (exit 0, 14/14 PASS, empty stderr), and generated `docs/poc/redaction-poc-output.md` from the captured stdout | Candidate approved the script plan with two wording corrections (see §5), reviewed the test results, requested final wording checks, and approved staging. Commit 3 not yet approved or created |

ChatGPT reviews of Claude Code's plans took place between these sessions (October 2026, including
2026-10-28). The candidate reports that these reviews contributed to identifying several of the concerns
behind the refinements, corrections and adjustments in rows 4–6.

## 5. AI suggestions rejected or modified
| Suggestion | Proposed by | Outcome | Reason |
|------------|-------------|---------|--------|
| HMAC-keyed hash chain | Claude Code (as an alternative) | Rejected in the plan direction approved by the candidate | Export recipients would need the secret |
| Trust a public key embedded in the export bundle | Claude Code (as an alternative) | Rejected | An attacker could re-sign; the key must arrive out of band |
| Offset pagination | Claude Code (as an alternative) | Rejected | Unstable under concurrent appends |
| Merkle tree log | Claude Code (as an alternative) | Deferred | Not justified within the time budget |
| Export only the matching records | Claude Code (early design) | Modified by Claude Code | Added hash skeleton and signed manifest so gaps and reordering are detectable |
| AWS, Docker, metrics in scope | Claude Code (plan v2) | Cut by the candidate | Outside the scenarios and the time budget |
| Treat retained `payloadRoot` as proof of archived content | Claude Code (plan v3) | Modified by candidate correction | Proves metadata consistency only; content needs the signed digest checked against the file |
| Treat a chained redaction event as authorized | Claude Code (plan v3) | Modified by candidate correction | Chaining is not authentication; authorizations are Ed25519-signed |
| AI log claim that no assignment material reached other services | Claude Code (plan v3 draft) | Rejected by candidate correction | Not verifiable by Claude Code, and the material had been shared with ChatGPT |
| DESIGN.md status "approved" | Claude Code (plan v3.1 draft) | Changed to "Proposed" by candidate adjustment | Approval is recorded only when the candidate gives it explicitly |
| Co-Authored-By trailer on commits | Claude Code | Rejected by the candidate | This log provides traceability |
| Lock file from `pip freeze` | Claude Code | Modified by the candidate | Lock must be generated from the declared dependencies |
| Describe removing value and salt in the PoC as deletion | Claude Code (commit 3 plan) | Modified by candidate correction | It is logical redaction from an in-memory structure, not secure deletion |
| Describe per-leaf salts as making equal values in different records "unlinkable" | Claude Code (commit 3 plan) | Modified by candidate correction | Salts only prevent inferring equality by comparing commitments; other fields may still link records |

## 6. Errors and corrections during AI-assisted work
- Claude Code's first `git commit` attempt for commit 1 failed because PowerShell passed the message as a
  pathspec. Nothing was committed; the commit was retried with a message file.
- A `gh api --jq` filter failed because of PowerShell quoting; it was rerun with a simpler filter.
- The Linux wheel dry-run first failed because only one platform tag was passed; it was rerun with the
  full manylinux tag set.
- The first draft of the PoC output document described the embedded stdout as "byte-for-byte"; the
  assembly step had converted CRLF line endings to LF, so the wording was corrected to state that
  transformation before review.

## 7. Verification policy
- Every file change, install, commit and push requires candidate approval.
- Test and tool results are recorded only from actual runs.
- ChatGPT's suggestions are advisory; repository implementation is done with Claude Code and reviewed by
  the candidate.
