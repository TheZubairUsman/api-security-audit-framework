# Contributing to API Security Audit Framework

Thank you for your interest in contributing! This project thrives on community involvement. Please read this guide to understand how to propose changes, report issues, and submit pull requests (PRs).

## Table of Contents
- Code of Conduct
- Ways to Contribute
- Getting Started
- Development Workflow
- Branching Strategy
- Commit Message Convention
- Pull Request Guidelines
- Code Style and Linting
- Tests and Validation
- Documentation Standards
- Adding Examples and Scripts
- Security Policy
- Release and Versioning
- Questions and Support

## Code of Conduct
By participating in this project, you agree to uphold a respectful, inclusive environment. Be kind, be constructive, and respect diverse perspectives.

## Ways to Contribute
- Report bugs and suggest enhancements via GitHub Issues
- Improve documentation in `docs/` and `checklists/`
- Add new automated scans in `tools/scripts/`
- Create security examples in `examples/`
- Enhance CI/CD workflows in `.github/workflows/`

## Getting Started
1. Fork the repository on GitHub
2. Clone your fork
   ```bash
   git clone https://github.com/TheZubairUsman/api-security-audit-framework.git
   cd api-security-audit-framework
   ```
3. Validate your environment
   ```bash
   chmod +x tools/scripts/validate-framework.sh
   ./tools/scripts/validate-framework.sh
   ```
4. Install recommended tooling (optional but helpful)
   ```bash
   npm install -g newman newman-reporter-html markdown-link-check
   pip3 install flask requests jsonschema pyyaml
   ```

## Development Workflow
- Search existing issues before filing a new one
- Open a Draft PR early to gather feedback for larger changes
- Keep changes focused and atomic; avoid unrelated refactors in a single PR

## Branching Strategy
- `main`: stable code, protected by CI
- `develop` (optional): integration branch for larger features
- Feature branches: `feat/<short-topic>`
- Fix branches: `fix/<short-topic>`
- Docs branches: `docs/<short-topic>`

Example:
```bash
git checkout -b feat/graphql-scanner
```

## Commit Message Convention
Use Conventional Commits to keep history consistent:
```
<type>(scope): short description

[body]
[footer]
```
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`.

Examples:
- `feat(scripts): add comprehensive-scan.sh orchestration`
- `fix(ci): correct artifact upload path`
- `docs(readme): add GraphQL guide references`

## Pull Request Guidelines
- One logical change per PR
- Link related issues (e.g., `Closes #123`)
- Include before/after behavior when applicable
- Update `README.md` if user-facing behavior changes
- Add or update documentation under `docs/` and checklists under `checklists/`
- Ensure CI passes (GitHub Actions workflow: `.github/workflows/api-security-audit.yml`)

### PR Checklist
- [ ] Code builds and runs locally
- [ ] `tools/scripts/validate-framework.sh` passes
- [ ] Updated or added tests (if applicable)
- [ ] Updated docs/checklists/templates (if applicable)
- [ ] No secrets/keys in code or commit history

## Code Style and Linting
While this repo is language-agnostic, follow these guidelines:

- Python (`*.py`)
  - Prefer Python 3.9+
  - Style: PEP 8 (use `ruff`/`flake8` if available)
  - Virtual env recommended for local testing

- JavaScript/Node (`*.js`)
  - Target Node 18+
  - Prefer `eslint` (if available) and consistent semicolons

- Shell (`*.sh`)
  - Use `bash` with `set -euo pipefail`
  - Validate with `shellcheck` (if available)
  - Ensure executables have `chmod +x`

- Markdown (`*.md`)
  - Use `#`-based headings, fenced code blocks with language
  - Validate links with `markdown-link-check` (optional)

## Tests and Validation
Use the built-in validation and CI to maintain quality:

- Local validation
  ```bash
  ./tools/scripts/validate-framework.sh
  ```
- CI workflow (runs on PR/merge/schedule)
  - Validates scripts with `shellcheck`
  - Validates Postman collections via Newman
  - Compiles Python examples
  - Generates and uploads artifacts

## Documentation Standards
- Place guides in `docs/` (e.g., `docs/graphql-security.md`)
- Place checklists in `checklists/` (e.g., `checklists/graphql-security-checklist.md`)
- Keep `README.md` up-to-date with new features, scripts, and examples
- Use descriptive headings, short paragraphs, and example snippets

## Adding Examples and Scripts
- Examples go under `examples/common-vulnerabilities/` with clear subfolders
  - Example: `examples/common-vulnerabilities/authentication-bypass/`
- Scripts go under `tools/scripts/`
  - Ensure usage/help sections (`--help`)
  - Include safe defaults and environment variable support

## Security Policy
- Do not include secrets, tokens, or credentials in code or examples
- For suspected security vulnerabilities, report privately (do not open a public issue)
- Provide reproduction steps and scope; we will coordinate a responsible disclosure

Contact for security issues:
- Email: zus3cu@gmail.com

## Release and Versioning
- Version: Semantic Versioning (SemVer)
- Changelog: derive from PR titles and commit messages

## Questions and Support
- Issues: https://github.com/TheZubairUsman/api-security-audit-framework/issues
- Discussions/Chat: Discord invite in `README.md`

Thank you for helping make API Security Audit Framework better and more secure!
