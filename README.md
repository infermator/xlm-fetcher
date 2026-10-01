# XML fetcher

A small public GitHub Actions runner for a trusted private XML import worker. It retrieves only explicitly listed worker files at an immutable private commit, runs them on this repository's standard Linux runner, and removes temporary data afterwards. It does not dispatch computation to a private repository. Source definitions, normalization, publication and database logic stay private.

No AI provider, commercial proxy, larger runner, public feed artifact or private code cache is involved. GitHub's documentation states standard hosted runners in public repositories are free; object/database/mail and other external services remain independently billed. Source access must be tested from the actual runner. This is scheduled batch processing, not an always-on service or a guaranteed exact timer.

## Setup

Create a public repository named `xlm-fetcher` (name retained intentionally) and copy this package's contents to its root, including `.github/workflows`. Set default branch to `main`. Do not publish the surrounding private integration notes or any worker code/configuration.

Create an Actions environment named `worker`. Restrict deployment branches to the protected `main` branch. Limit repository write access to trusted operators; protect workflow changes and do not enable secrets on fork pull requests or use pull_request_target. The public checks workflow has no credentials. The production workflow accepts only schedule and manual dispatch on main.

Configure these **environment secrets**, not public files or variables:

| Secret | Purpose |
| --- | --- |
| PRIVATE_REPOSITORY | Private owner/repository name |
| PRIVATE_WORKER_REF | Reviewed immutable 40-character commit SHA |
| PRIVATE_READ_TOKEN | Fine-grained token: Contents read-only for that private repository only; metadata read is inherent |
| PRIVATE_FEED_URL | Approved complete source URL used for the read-only acquisition probe |
| PRIVATE_SOURCE_ID | Authoritative private-worker source selector |
| SUPABASE_URL | Private worker's approved database endpoint |
| SUPABASE_SECRET_KEY | Private worker import credential; never supplied to probe/tests/bootstrap |

Prefer a narrowly scoped, expiring read credential; rotation must be documented. The public GITHUB_TOKEN cannot read another private repository. Do not reuse a full account/admin PAT or credentials from another application. A public repo cannot be anonymous about its owner, timing and workflow structure; this package anonymizes source/application content and logs, not account attribution.

Run manual `XML worker` → `probe` first. It fetches private code, verifies the pinned requirements and private tests, then downloads and fully validates the source without DB credentials. Public results contain phase/status and allowlisted error category only. Download contents, hashes/counts/URLs and private tracebacks remain transient private files, never uploaded as Actions artifacts. A 403 challenge stops; the worker must not bypass it. A 503/backend failure may be retried by the private transport.

Run manual `import` only after source access, database headroom, backup/restore and current-worker full publication gates have been reviewed. The importer loads the source URL from the database itself, preserving source identity/lease ownership; the probe URL is not silently published under another source. It runs snapshot pruning only after successful import. Run and compare an identical accepted-snapshot replay, controlled price/content/removal/failure cases and the private import ledger before certifying the integration.

Only then set repository variable `SCHEDULE_ENABLED=true`. Its unset/default value keeps the 30-minute schedule disabled. Cron is `17,47 * * * *` UTC, offset from the busy top of the hour. Disable every other import scheduler for the same sources first. Monitor accepted-source observation age independently of Actions run color. GitHub schedules can be delayed or dropped, and public-repo schedules can be disabled after prolonged repository inactivity; do not depend on permanent unattended scheduling without monitoring.

## Operation and privacy

Public logs show generic phase outcomes. The runner never prints private exceptions, commands, source bodies, API response content, dependency output or worker stdout. Do not enable Actions/step debug or shell trace with private configuration. Debug a failure through the private import ledger/operator channel; if acquisition alone fails, the public allowlisted reason distinguishes a challenge, origin failure or incomplete body without exposing its endpoint.

The read token exists only in the prepare step. Subprocess environments exclude it; only import/retention processes receive database credentials. Private files are temporary and not committed/cached/uploaded. Child runtime and log size are bounded; dependencies must match the reviewed exact allowlist. Changing worker dependencies or its immutable ref requires operator review. A pinned private commit does not update automatically whenever main changes.

Repository writers could alter a secret-bearing workflow: branch protection, environment branch restriction and trusted access are required configuration, not guarantees from hiding strings. Workflows on fork pull requests run public generic tests only. Do not merge unreviewed workflow/runner changes or generate executable commands from public dispatch inputs.

Validate locally with `python3 -m unittest discover -s tests -p 'test_*.py'`. No private credentials or network are used by these contract tests. A passing local test does not prove real cross-repository authorization, source access or hosted database publication; record those separately after actual Actions executions.

Official references:

- https://docs.github.com/en/billing/concepts/product-billing/github-actions
- https://docs.github.com/en/actions/concepts/billing-and-usage
- https://github.com/actions/checkout
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule
