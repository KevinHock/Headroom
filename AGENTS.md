# AGENTS.md

Read [CLAUDE.md](CLAUDE.md) first, before exploring the codebase or editing anything, and follow it.

It is the single source of truth for how to work here: the truth hierarchy between the specification corpus and the code, the guardrails that apply to every change, the two routing tables naming what a given change must open, and what counts as done.

The corpus itself is [`spec/`](spec/README.md). Its manifest carries the authority model and a routing table from any file you are touching to the specifications that govern it.

This file exists only to point there. Nothing is repeated here, so anything you find only in this file is out of date.
