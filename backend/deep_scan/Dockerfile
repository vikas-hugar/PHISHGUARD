# ==============================================================================
# PhishGuard AI V6.2 — Dedicated Deep Scan Browser Isolation Sandbox
# ==============================================================================
# Security Hardened Container:
# - Minimal isolated Playwright + Chromium runtime
# - Non-root unprivileged execution user (sandboxuser)
# - No user files, no host browser profiles, no host credentials or cookies
# - Read-only root filesystem with ephemeral memory-only /tmp
# ==============================================================================

FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

# Set environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOME=/tmp

# Security: Create non-root unprivileged sandbox execution user
RUN groupadd -g 10001 sandboxgroup && \
    useradd -u 10001 -g sandboxgroup -s /usr/sbin/nologin -M -d /tmp sandboxuser

# Workdir inside container
WORKDIR /app

# Copy ONLY the dedicated analysis agent (no project files or host data)
COPY sandbox_agent.py /app/sandbox_agent.py

# Ensure correct permissions
RUN chown -R 10001:10001 /app && \
    chmod 755 /app && \
    chmod 644 /app/sandbox_agent.py

# Switch to unprivileged sandbox user
USER 10001:10001

# Entrypoint receives target URL as single argument
ENTRYPOINT ["python3", "/app/sandbox_agent.py"]
