# Guardrail Layer for LLM Agents

A fully automated safety layer for LangChain agents. Every tool call is screened by a FastAPI gateway before it runs. The layer detects prompt injection in user input, retrieved documents and tool outputs. Risky calls go to an automated adjudicator: deterministic argument-provenance and budget checks plus local open-source LLM judges. Every decision is recorded in a hash-chained PostgreSQL audit log.

> Status: under active development.

## Stack

Python · LangChain · FastAPI · PostgreSQL · Redis · Ollama · Docker · pytest
