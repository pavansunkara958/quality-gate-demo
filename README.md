# Custom CI/CD Security & Quality Gate: build procedure

A step-by-step procedure for the "Custom CI/CD Code Security & Quality Gate System" assignment, written around the starter kit in this folder. The kit's scanner was tested locally against clean and vulnerable commits with a mock LLM; the GitHub workflow and the dashboard page have not been run on GitHub yet, so Step 6 is where you prove them.

## What you are building

```
contributor pushes / opens PR ──► GitHub Actions workflow (quality-gate)
                                     │
                                     ├─ scanner/scan.py
                                     │    1. git diff of the push
                                     │    2. regex + entropy rules  → secrets
                                     │    3. Shade LLM (glm-flash)  → vulnerabilities, bugs
                                     │    4. gate policy            → PASSED / REJECTED
                                     ├─ comment on the PR or commit (why it failed + dashboard link)
                                     ├─ scanner/publish.py → JSON report committed to gh-pages
                                     └─ exit 1 if REJECTED → required status check fails → merge blocked

GitHub Pages serves gh-pages ──► dashboard/index.html reads data/index.json + data/reports/*.json
```

| File | Purpose |
|---|---|
| `.github/workflows/quality-gate.yml` | Triggers on every PR and push to the target branch, runs the scan, posts feedback, publishes, enforces |
| `scanner/scan.py` | Diff parser, secret rules, Shade LLM call, finding validation, gate policy (standard library only) |
| `scanner/publish.py` | Adds a report to the dashboard data folder and updates the index |
| `dashboard/index.html` | Static dashboard: activity feed, metrics, line-level inspector (no build step) |
| `.github/branch-protection.json` | Branch protection settings applied with one `gh` command |

## Decisions already made in the kit

- **Hosting: GitHub Pages.** It is the spec's recommended option and needs no server. **AWS free tier is not needed for this assignment.** Keep it as a fallback only: if the assigned repo is private on a plan without Pages, host the same static files in an S3 bucket.
- **Secrets are decided by rules, not by the LLM.** Provider key formats (AWS, GitHub, Stripe, private keys, and so on) always fail. Looser patterns (`password = "..."`, connection strings) must pass an entropy and placeholder check, which is what keeps clean code from being blocked.
- **The LLM handles vulnerabilities and bugs.** Each finding it returns is dropped unless it points to a line the push actually added. An LLM "secret" finding is kept only if that line really contains a secret-looking string.
- **Fail closed.** If the LLM is unreachable after 3 tries, or its credentials are missing, the gate rejects. Change with the repo variable `LLM_FAIL_MODE=open`.
- **Published reports redact secrets.** The dashboard is public, so only the first 4 characters of a detected secret are stored.

## Two things to confirm before you rely on the kit

1. **Shade LLM API shape.** `call_llm()` assumes an OpenAI-compatible chat completions endpoint (`POST` with `model` and `messages`, bearer key, answer in `choices[0].message.content`). The model name format suggests this, but it is an assumption. Test it:
   ```bash
   curl -s "$SHADE_API_URL" -H "Authorization: Bearer $SHADE_API_KEY" -H "Content-Type: application/json" \
     -d '{"model":"z-ai/glm-flash-latest","messages":[{"role":"user","content":"Reply with the word ok"}]}'
   ```
   If the request or response format differs, `call_llm()` is the only function to change.
2. **Repo plan.** On a free personal account, GitHub Pages and branch protection only work on **public** repos. Ask the evaluators whether the assigned repo is public or on a paid organization plan.

## Step 0: Install tools

- Git, Python 3.10 or newer, VS Code
- GitHub CLI: https://cli.github.com, then sign in:
  ```bash
  gh auth login
  ```

## Step 1: Phase 1 brief (submit this first)

The spec gives you the assigned branch only after this is approved. Keep it to 2–3 pages:

1. **SonarQube:** scanner runs in CI, results go to a server, a Quality Gate (conditions on new code) returns PASSED/FAILED, and the pipeline fails on FAILED. Findings are grouped as Vulnerabilities, Security Hotspots, Bugs and Code Smells, each with a severity, and shown on a dashboard.
2. **CodeRabbit:** a GitHub App receives PR webhooks, pulls the diff hunks plus surrounding context, sends them to LLMs, and posts line-level review comments with suggested fixes.
3. **Your design:** paste the diagram above and cover the three required areas:
   - *Event interception:* Actions workflow on `pull_request` and `push`, plus branch protection with the required check `quality-gate`.
   - *Hybrid pipeline:* rules for secrets, LLM for vulnerabilities and bugs, validation of LLM output against changed lines.
   - *Dashboard sync:* each CI run commits a JSON report to `gh-pages`, and Pages serves a static dashboard that reads it.
4. **Limits to state openly** (evaluators tend to ask):
   - GitHub Actions runs after a push arrives, so "rejecting a push" means: direct pushes to the protected branch are refused, and PRs with a failing check cannot merge.
   - A secret pushed to any branch is already exposed, even if the PR is blocked. It must be rotated.
   - A PR could edit the workflow or scanner itself. Mitigation: require review for `.github/` and `scanner/` via CODEOWNERS, or run the scanner from the base branch.
   - PRs from forks do not receive repository secrets. Contributors must push branches to the same repo.

## Step 2: Create a practice repo and push the kit

Build and test in your own public repo while Phase 1 is reviewed. Unzip the kit, open the folder in VS Code, and run these in the VS Code terminal.

```bash
git init -b main
git add .gitignore
git commit -m "chore: initial commit"

# create the GitHub repo and push main (main becomes the default branch)
gh repo create quality-gate-demo --public --source . --remote origin --push

# create the empty dashboard branch
git switch --orphan gh-pages
git commit --allow-empty -m "chore: init dashboard branch"
git push -u origin gh-pages
git switch main
```

Your other kit files stay in the folder as untracked files during this; that is expected.

## Step 3: Turn on GitHub Pages and add the LLM credentials

```bash
# serve the gh-pages branch
gh api -X POST "repos/{owner}/{repo}/pages" -f "source[branch]=gh-pages" -f "source[path]=/"

# store Shade credentials as GitHub Secrets (each command prompts you to paste the value)
gh secret set SHADE_API_URL
gh secret set SHADE_API_KEY

# optional settings
gh variable set SHADE_MODEL --body "z-ai/glm-flash-latest"
gh variable set BUG_BLOCK_SEVERITIES --body "CRITICAL"
```

`SHADE_API_URL` is the full chat completions URL. The UI route for Pages is Settings → Pages → Deploy from a branch → `gh-pages` / root.

## Step 4: Test the scanner locally

```bash
git add -A
git commit -m "feat: scanner, workflow and dashboard"

# rules only, no LLM needed
python scanner/scan.py --base HEAD~1 --head HEAD --no-llm
```

Expected: `Quality gate: PASSED`. To try the LLM locally, set the variables first.

```bash
# macOS / Linux / Git Bash
export SHADE_API_URL="..." SHADE_API_KEY="..."
# Windows PowerShell
$env:SHADE_API_URL="..."; $env:SHADE_API_KEY="..."

python scanner/scan.py --base HEAD~1 --head HEAD
```

Output lands in `out/report.json` and `out/summary.md` (ignored by git).

## Step 5: Push to GitHub and protect the branch

```bash
git push origin main
gh run watch              # follow the first workflow run
```

The first run should pass, and `https://<your-username>.github.io/quality-gate-demo/` should show one entry within a minute or two. Then lock the branch:

```bash
gh api -X PUT "repos/{owner}/{repo}/branches/main/protection" --input .github/branch-protection.json
```

This requires a pull request and a passing `quality-gate` check, with no bypass for admins. The check name only becomes selectable after the workflow has run once, which is why this step comes after the first push.

## Step 6: Run your own adversarial tests

Run each test from a fresh branch off `main`.

**Test A: clean change (must pass)**
```bash
git switch main && git pull
git switch -c test/clean
# add a small harmless file, for example hello.py with a function that adds two numbers
git add -A && git commit -m "feat: add helper"
git push -u origin test/clean
gh pr create --base main --fill
gh pr checks --watch
gh pr merge --squash --delete-branch
```

**Test B: leaked key (must be rejected)**
```bash
git switch main && git pull
git switch -c test/secret-leak
```
Create `config.py` with two lines:
- `AWS_ACCESS_KEY_ID = "..."` where the value is `AKIA` followed directly by `IOSFODNN7EXAMPLE` (AWS's documented fake key)
- `db_password = "..."` where the value is any 12 or more random characters

The values are written apart here on purpose: the gate scans this README too, and a complete fake key in it would get the kit's own commit rejected.
```bash
git add -A && git commit -m "test: hardcoded key"
git push -u origin test/secret-leak
gh pr create --base main --fill
gh pr checks --watch        # quality-gate should fail
gh pr merge --squash        # should be refused
```

**Test C: SQL injection (must be rejected by the LLM)**
```bash
git switch main && git switch -c test/sqli
```
Create `users.py` containing:
```python
import sqlite3

def find_user(name):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()
```
```bash
git add -A && git commit -m "test: sql injection"
git push -u origin test/sqli
gh pr create --base main --fill
gh pr checks --watch
```

**Test D: direct push to the protected branch (must be refused by GitHub)**
```bash
git switch main
git commit --allow-empty -m "test: direct push"
git push origin main        # expect "protected branch" rejection
git reset --hard origin/main
```

After each test, check three things: the PR comment lists the findings, the check status is right, and the dashboard shows the new entry with the inspector details.

## Step 7: Tune before the demo

- **False positives:** push 5–10 varied clean changes (config files, tests, docs, a refactor). If the LLM blocks clean code, tighten `SYSTEM_PROMPT` in `scan.py`. Keep temperature at 0.
- **Missed issues:** try command injection (`os.system` with user input), path traversal, `pickle.loads` on request data, `verify=False`, and CORS `*` with credentials.
- **Bug threshold:** `BUG_BLOCK_SEVERITIES` controls which bug severities block (default `CRITICAL`).
- **Credit use:** each changed file is one LLM call. Lock files, images and minified files are skipped.

## Step 8: Move to the assigned repo

Once the evaluators give you the repo and branch:

```bash
git clone https://github.com/<org>/<assigned-repo>.git
cd <assigned-repo>
git switch <assigned-branch>
git switch -c setup/quality-gate
# copy .github/, scanner/, dashboard/, .gitignore, .env.example and README.md into this folder
```

Then:
1. In `.github/workflows/quality-gate.yml`, change `main` to `<assigned-branch>` in both `branches:` lines.
2. Repeat the `gh-pages` commands from Step 2 and all of Step 3 in this repo.
3. Push and merge the setup branch:
   ```bash
   git add -A && git commit -m "feat: custom security quality gate"
   git push -u origin setup/quality-gate
   gh pr create --base <assigned-branch> --fill
   ```
4. Apply branch protection as in Step 5, replacing `main` in the URL with `<assigned-branch>`. If you are not a repo admin, send the evaluators `.github/branch-protection.json` and ask them to apply it.
5. Rerun Tests A–D.

## Step 9: Demo checklist

- Dashboard URL open, plus the Actions tab and the PR list
- One passed and one rejected PR already in the feed, so the trend and metrics are not empty
- Be ready to explain: the push-versus-merge point, why rules decide secrets, how LLM findings are validated, fail-closed behaviour, and secret redaction
- Setup documentation: this README covers the deliverable

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Checkout dashboard branch" step fails | `gh-pages` branch does not exist yet (Step 2) |
| Gate rejects with "LLM review could not complete" | Secrets missing or wrong URL; run the `curl` test above |
| Dashboard returns 404 | Pages not enabled, or first deploy still building (see the "pages build and deployment" run in Actions) |
| PR comment step fails with 403 | Org restricts workflow token permissions (Settings → Actions → General → Workflow permissions), or the PR is from a fork |
| `git push` of a test secret is blocked before CI runs | GitHub's own push protection caught it; that is separate from your gate. Use a different fake value |
| `quality-gate` not offered as a required check | The workflow has not completed a run on this repo yet |
