# Contributing to Don't Lie To Me – Azure

Thank you for your interest in contributing! This document provides guidelines
to help you get started quickly.

---

## Code of Conduct

Be respectful, constructive, and inclusive. We follow the
[Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

---

## How to contribute

### Reporting bugs or requesting features

1. Search [existing issues](https://github.com/linkenthegreat/dont_lie_to_me_azure/issues)
   to avoid duplicates.
2. Open a new issue using one of the provided templates.
3. Include as much context as possible (OS, Python version, error messages,
   steps to reproduce).

### Submitting a pull request

1. Fork the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Follow the setup instructions in [docs/setup.md](setup.md).
3. Make your changes and add or update tests where appropriate.
4. Ensure the code follows the style guide (see below).
5. Commit with a clear message:
   ```
   feat: add rate-limiting middleware to all endpoints
   ```
6. Push your branch and open a pull request against `main`.
7. Fill in the pull request template and link any related issues.

---

## Project structure

```
dont_lie_to_me_azure/
├── src/
│   ├── backend/           # Azure Functions (Python v2)
│   │   ├── function_app.py
│   │   ├── host.json
│   │   ├── requirements.txt
<<<<<<< HEAD
<<<<<<< HEAD
│   │   ├── prompts.yaml  # Centralized AI system prompts
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
│   │   ├── local.settings.json.example
│   │   └── shared/        # Reusable helpers
│   │       ├── ai_client.py
│   │       ├── keyvault.py
<<<<<<< HEAD
│   │       ├── prompts.py # Prompt loader with fallback
│   │       └── config.py
=======
│   │   ├── local.settings.json.example
│   │   └── shared/        # Reusable helpers
│   │       ├── ai_client.py
│   │       ├── keyvault.py
│   │       └── storage.py
>>>>>>> origin/main
=======
│   │       └── storage.py
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
│   └── frontend/          # Static web UI
│       ├── index.html
│       ├── style.css
│       └── app.js
├── infra/                 # Bicep IaC templates
│   ├── main.bicep
│   └── modules/
│       ├── functions.bicep
│       ├── keyvault.bicep
│       └── storage.bicep
├── docs/                  # Documentation
│   ├── architecture.md
<<<<<<< HEAD
<<<<<<< HEAD
│   ├── architecture_v3.mmd # Mermaid diagram (v3 = prompt system)
=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
│   ├── setup.md
│   └── CONTRIBUTING.md
└── README.md
```

<<<<<<< HEAD
<<<<<<< HEAD

## AI Prompt Management

### Architecture (v3.0)

System prompts for AI agents are centralized in `src/backend/prompts.yaml`.
This approach allows prompt engineers to iterate without modifying code.

**Fallback Strategy:**
- Each service module contains an embedded `_FALLBACK_SYSTEM_PROMPT` constant
- If `prompts.yaml` is missing or invalid, services automatically use the fallback
- This ensures the system remains operational even if external config fails

### Editing Prompts

**To modify AI behavior:**
1. Edit `src/backend/prompts.yaml`
2. Change the `system_prompt` text for the relevant service
3. Optionally adjust `model`, `temperature`, or `max_tokens`
4. Test locally (no code changes required)
5. Commit the YAML file

**Example:**
```yaml
scam_classifier:
   system_prompt: |
      You are an expert anti-scam analyst...
   model: gpt-4o-mini
   temperature: 0.2
   max_tokens: 500
```

### Fallback Constants (for developers)

**When changing service logic:**
- Keep the embedded `_FALLBACK_SYSTEM_PROMPT` in sync with `prompts.yaml`
- This ensures consistent behavior if YAML fails to load
- The fallback is **not** the primary prompt – it's a safety net

**Code pattern:**
```python
from shared.prompts import get_prompt_config

# Embedded fallback - operational resilience if YAML fails
_FALLBACK_SYSTEM_PROMPT = "Your prompt here..."

# Load from YAML with fallback to embedded constant
_config = get_prompt_config("service_key")
_SYSTEM_PROMPT = _config.get("system_prompt", _FALLBACK_SYSTEM_PROMPT)
```

**When to update fallback:**
- Always update both YAML and fallback in the same commit
- Fallback should match the production YAML prompt
- Think of it as: YAML = source of truth, fallback = disaster recovery

### Dependencies

The prompt loader requires PyYAML:
```bash
pip install pyyaml
```

If PyYAML is not installed, services automatically fall back to embedded prompts.

=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
---

## Code style

### Python (backend)

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use type hints where practical.
- Docstrings for all public functions and classes.
- Lint with `flake8` and format with `black`:
  ```bash
  pip install black flake8
  black src/backend/
  flake8 src/backend/
  ```

### JavaScript (frontend)

- Use ES6+ features.
- Prefer `const` / `let` over `var`.
- No external dependencies required for the starter – keep it vanilla JS.

### Bicep (infra)

- Use modules for logical separation.
- Add `@description` decorators to all parameters.
- Follow [Bicep best practices](https://learn.microsoft.com/azure/azure-resource-manager/bicep/best-practices).

---

## Testing

```bash
cd src/backend
pip install pytest
pytest tests/ -v
```

Please add tests for any new backend functionality under `src/backend/tests/`.

---

## Branch naming conventions

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feature/<short-description>` | `feature/add-image-ocr` |
| Bug fix | `fix/<short-description>` | `fix/keyvault-timeout` |
| Documentation | `docs/<short-description>` | `docs/update-setup-guide` |
| Infrastructure | `infra/<short-description>` | `infra/add-cosmos-module` |

---

## Commit message format

We loosely follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

[optional body]
[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `infra`.

---

## Questions?

Open a [GitHub Discussion](https://github.com/linkenthegreat/dont_lie_to_me_azure/discussions)
or ping the maintainers in an issue.
