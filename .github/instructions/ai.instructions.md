---
description: Load these on every request
applyTo: '**' # when provided, instructions will automatically be added to the request context when the pattern matches an attached file
---

<!-- Tip: Use /create-instructions in chat to generate content with agent assistance -->

This repository is a collection of research scripts to analyze git repositories and their vulnerability histories. The scripts are designed to assist in processing historical security issues from places like the OSV and NVD, tracking changes over time, and understanding the evolution of vulnerabilities within a codebase.

The scripts are intended to be used as tools for researchers and developers who need to understand the security history and vulnerability patterns of software projects. They provide mechanisms for extracting, analyzing, and visualizing data related to past vulnerabilities, helping users to identify trends and potential risks in software development.

Everything should be configurable to run on small numbers of repositories as well as large-scale analyses. This will run on a supercomputer environment with SLURM, leveraging parallel processing and high-performance computing resources to efficiently handle extensive datasets and complex analyses. 