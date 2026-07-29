# ADR 0057: Official Codex browser capability boundary

Status: Accepted

## Context

The product brief requires CoCodex to preserve official Codex browser functionality where the host runtime supports it, expose browser status safely, and never send browser credentials, cookies, passwords, or authentication storage to CoCodex Server. CoCodex agents currently execute through `codex exec --json`. The current official Codex manual states that Browser is unavailable in Codex CLI and is provided by the official desktop app. The installed Codex 0.146 runtime advertises stable browser feature flags and an installed Browser plugin, but those facts do not make Browser available to a `codex exec` child.

## Decision

CoCodex models the execution surface explicitly. A local, shell-free probe of the exact selected Codex runtime runs only bounded read-only commands: `features list`, `plugin list`, and `app --help`. It projects versioned booleans and the bounded runtime version; it never returns executable paths, plugin paths, marketplace paths, configuration, cookies, browser state, credentials, or raw command output.

`agentBrowserAvailable` remains false for the `codex-exec` surface even when the official app, browser flags, and Browser plugin are present. The GUI says `Official Codex app`, not `enabled`, and explains that hosted CoCodex agents cannot use Browser through CLI.

An explicit user action may open a configured agent workspace in the official Codex app. The renderer sends only the agent ID. The resident Client resolves that ID to the canonical locally stored policy and invokes the selected runtime with shell-free argv `app <stored-workspace>`. Renderer-supplied paths, commands, flags, URLs, environment values, and credentials are rejected. CoCodex never launches the official app automatically.

## Consequences

This closes false capability claims and provides a safe official-app handoff, but it does not claim browser-task execution, watch/shared-control state, or browser event streaming for hosted agents. Those remain incomplete until OpenAI exposes a supported programmatic contract that CoCodex can integrate without rebuilding or redistributing the proprietary Browser runtime.

The detector is local-only and read-only. It does not contact CoCodex Server, mutate Codex settings, inspect browser profiles, or alter Sunshine/OpenCodex processes or ports.

## Verification

Tests cover installed-app-only detection, every missing component failing closed, no CLI browser claim, shell-free exact app argv, renderer path/command rejection, resident-session projection without local paths, GUI presentation, TypeScript, and production rendering.
