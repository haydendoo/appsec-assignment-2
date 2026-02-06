# AGENTS.md
This file defines how AI agents must behave when working in this repository.
Follow these rules strictly. When unsure, ask before making changes.

## Project Overview
This is a asp.net core web application and uses SQLite for database with Entity Framework Core. It uses bootstrap as its component library.

## General Rules (Very Important)
- Follow *best practices* at all times
- Keep changes *minimal and focused*
- Do *not* change architecture unless explicitly requested
- Prefer clarity over cleverness
- Use proper dependency injection

## Comments & Documentation Rules

- Do NOT add comments that restate obvious code behavior
- Do NOT comment every line or block
- Do NOT add "AI-style" explanatory comments

Comments are allowed *only when they add real value*, such as:
- Explaining why a decision was made
- Clarifying non-obvious business rules
- Documenting edge cases or constraints
- Warning about pitfalls or side effects

## Standards
Always make code consistent and standardised. Try to use existing code as a reference on how you can implement new features (like existing utility functions, existing viewmodels and the code structure as reference)

## Secret Management
Never hardcode secrets and always use safe methods to get secrets like api keys