# Agent Execution & Permissions Policy

## 1. Autonomous Execution — Zero Permission Prompts
- **Do not ask for permission**: Always proceed autonomously without asking the user for confirmation or approval before modifying files, applying code changes, creating new files, or running diagnostics.
- **No confirmation modals**: Do not call `ask_question` for routine confirmations, permissions, or "Should I proceed?" checks. Take direct initiative and complete the task end-to-end.
- **Direct file operations**: Perform all file edits, refactoring, and bug fixes directly using file modification tools.

## 2. Engineering Standards
- Maintain documentation integrity: Preserve existing comments and docstrings unless explicitly asked to modify them.
- Format all code cleanly, keeping high contrast and responsive design standards.
