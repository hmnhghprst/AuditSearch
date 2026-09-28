# AuditSearch

**ausearch-style auditd analysis directly inside Splunk.**

AuditSearch is a Splunk custom search command that brings practical `ausearch`-style capabilities to raw Linux `auditd` events **at search time**.

It allows security analysts and engineers to interpret and filter auditd events directly from SPL without modifying the original events, installing additional parsing tools on source servers, or transforming audit logs before they reach Splunk.

---

## Why AuditSearch?

Linux `auditd` provides detailed security and system activity logs, but working with those logs outside the Linux environment is not always straightforward.

On a Linux system, tools such as:

```bash
ausearch -i
ausearch -k rootcmd
ausearch -m EXECVE
```

make raw audit records significantly easier to analyze.

Once those same raw audit logs are forwarded to Splunk, however, the situation is different.

You can index the original auditd events, but Splunk does not natively provide the same `ausearch`-style interpretation of fields such as:

* `arch`
* `syscall`
* `PROCTITLE`
* negative `exit` values / errno
* hex-encoded audit fields
* auditd `key`
* audit record types
* login UID (`auid`)

There are several ways to address this.

### Parse at the source

An Add-on or other agent can transform auditd events into JSON or another structured format before forwarding them.

This can work, but production environments may have restrictions around:

* installing additional software
* modifying existing audit pipelines
* security approval
* configuration management
* performance impact on production hosts

### Process events before forwarding

A Universal Forwarder can potentially run scripts or other processing logic before sending events to Splunk.

Again, this introduces additional software and processing on the source system and may not be acceptable in tightly controlled environments.

### Parse at search time with Splunk configuration

`props.conf`, `transforms.conf`, and related mechanisms can provide useful field extraction.

However, field extraction alone does not reproduce the behavior and interpretation provided by `ausearch -i` and related audit tooling.

---

## The AuditSearch approach

AuditSearch takes a different approach:

**Keep the original auditd event untouched and perform the interpretation when the analyst searches it.**

```text
Linux auditd
     │
     │ raw audit.log
     │
     ▼
Universal Forwarder
     │
     │ untouched
     ▼
Splunk Index
     │
     │ raw _raw event
     ▼
Splunk Search
     │
     │ filters
     ▼
| auditsearch -i
     │
     ▼
Interpreted auditd fields
```

Nothing needs to be installed on the Linux source host beyond the existing log forwarding configuration.

There is:

* No source-side parsing
* No source-side JSON conversion
* No scripted input
* No `ausearch` dependency on the source server
* No Python dependency on the source server
* No source-side Add-on required
* No `props.conf` / `transforms.conf` field extraction shipped by AuditSearch
* No rewriting of indexed events

The original `_raw` event remains unchanged.

AuditSearch operates in the Splunk search pipeline and adds interpreted fields to the results.

---

# Quick Example

Raw auditd data can be searched directly:

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i
```

AuditSearch interprets fields such as `arch`, `syscall`, `PROCTITLE`, negative `exit` values, and other supported hexadecimal fields.

For example:

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i
| table _time host auid syscall exe comm PROCTITLE
```

The result is conceptually similar to taking raw auditd records and applying the useful interpretation normally associated with:

```bash
ausearch -i
```

but directly inside Splunk.

---

# Search Command

```text
auditsearch [-i] [-k <keyword> | key=<keyword>] [type=<TYPE>] [auid=<uid>]
```

All options are optional, order-independent, and can be combined.

## `-i` — Interpret Fields

Enable auditd field interpretation.

Equivalent forms:

```text
-i
i=t
i=true
```

Example:

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i
```

When enabled, AuditSearch interprets supported fields including:

* `arch`
* `syscall`
* `PROCTITLE`
* negative `exit` values as errno
* supported hex-encoded free-text fields

The original value is preserved as:

```text
<field>_raw
```

AuditSearch never overwrites the original value.

Without `-i`, only raw field extraction is performed.

---

## `-k <keyword>` — Filter by Auditd Key

Filter events by their auditd `key`.

Supported forms:

```text
-k <keyword>
-k=<keyword>
--key <keyword>
key=<keyword>
```

Example:

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i -k rootcmd
```

When `-i` is enabled, the comparison is performed against the decoded key.

---

## `type=<TYPE>` — Filter by Audit Record Type

Filter events by audit record type.

Examples include:

```text
SYSCALL
EXECVE
PATH
PROCTITLE
CWD
```

The comparison is case-insensitive.

Example:

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i type=EXECVE
```

---

## `auid=<uid>` — Filter by Login UID

Filter events by their audit login UID.

Example:

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i auid=1000
```

---

# Combined Usage

AuditSearch options can be freely combined.

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i -k rootcmd type=EXECVE
| table _time host auid comm exe
```

Another example:

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i auid=1000 type=SYSCALL
| table _time host auid syscall success exit
```

---

# Important: Filter Before `auditsearch`

> [!WARNING]
> **Always filter your events as much as possible before sending them to `auditsearch`.**

AuditSearch processes every event that reaches the command.

Interpretation and decoding require CPU and memory resources on the Splunk search infrastructure. The cost becomes particularly important when processing large volumes of auditd data.

Avoid:

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i
```

when the search actually needs only a small subset of the available events.

Instead, push your filtering as early as possible:

```spl
index=linux_audit sourcetype=auditd host=server01 "EXECVE"
| auditsearch -i
```

or:

```spl
index=linux_audit sourcetype=auditd
    (host=server01 OR host=server02)
    auid=1000
    "EXECVE"
| auditsearch -i
```

Then apply AuditSearch only to the events that actually need auditd interpretation.

### Why this matters

The recommended flow is:

```text
Splunk index
     │
     │ filter as much as possible
     ▼
Relevant auditd events
     │
     ▼
| auditsearch ...
     │
     ▼
Interpretation / decoding
     │
     ▼
Results
```

not:

```text
Splunk index
     │
     ▼
ALL auditd events
     │
     ▼
| auditsearch -i
     │
     ▼
Filter afterwards
```

For large auditd environments, this distinction can have a significant impact on search performance.

---

# Data Integrity

AuditSearch is designed to work **without modifying the original event**.

When a field is interpreted, its original value is retained as:

```text
<field>_raw
```

For example, conceptually:

```text
PROCTITLE       = decoded value
PROCTITLE_raw   = original auditd value
```

This allows analysts to work with human-readable values while retaining the original representation for verification and forensic purposes.

---

# Architecture

```text
┌──────────────────┐
│      auditd      │
│                  │
│ /var/log/audit/  │
│    audit.log     │
└────────┬─────────┘
         │
         │ raw audit.log
         │
         ▼
┌──────────────────────────┐
│   Splunk Universal       │
│       Forwarder          │
│                          │
│      No parsing          │
│      No rewriting        │
└────────┬─────────────────┘
         │
         │ raw events
         ▼
┌──────────────────────────┐
│     Splunk Indexers      │
│                          │
│      Original _raw       │
│        preserved         │
└────────┬─────────────────┘
         │
         │ Search
         ▼
┌──────────────────────────┐
│      SPL filtering       │
│                          │
│ host / source / type /   │
│ user / time / etc.       │
└────────┬─────────────────┘
         │
         │ relevant events
         ▼
┌──────────────────────────┐
│      auditsearch         │
│                          │
│ interpretation           │
│ decoding                 │
│ filtering                │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│   Interpreted Results    │
│                          │
│ Original _raw preserved  │
└──────────────────────────┘
```

AuditSearch does not require the source Linux host to know that AuditSearch exists.

The source only needs to forward the existing auditd log to Splunk.

---

# Search-Time Processing

AuditSearch intentionally performs its work at search time.

This means the indexed audit data remains the original auditd data rather than a transformed representation created by an ingestion-time parser.

This provides several practical advantages:

* Existing auditd forwarding configurations can remain unchanged.
* Production servers do not need additional parsing software.
* No source-side processing is required.
* Existing raw audit data remains available.
* Analysts can choose when interpretation is required.
* Different searches can apply different filters and interpretation options.

AuditSearch is therefore intended to complement existing Splunk auditd ingestion rather than replace it.

---

# Performance

AuditSearch is designed for search-time processing with attention to the typical volume of Linux auditd data.

Key implementation characteristics include:

* **Single-pass event processing** where applicable.
* Regex patterns are compiled once rather than recompiled for every event.
* Syscall and architecture lookup tables are loaded once at process startup.
* No network calls in the processing path.
* No blocking external I/O.
* Filters such as `type`, `auid`, and `key` are applied before more expensive interpretation where possible.
* The command is distributable, allowing Splunk to distribute processing rather than unnecessarily funneling all raw events through the search head.
* No external runtime dependency is required for normal processing.

Despite these optimizations, **search-time parsing is still processing**.

The amount of data passed to `auditsearch` directly affects resource consumption. Always narrow the event set before invoking the command when possible.

---

# Security

AuditSearch is designed to treat decoded audit content as data, not executable code.

The command does not use:

* `subprocess`
* `os.system`
* `eval`
* `exec`
* shell execution

Decoded values such as `PROCTITLE`, `exe`, `comm`, and other audit fields are treated as display and analysis data.

`shlex.quote()` is used where appropriate to make displayed command-line content safer to copy and paste. It does **not** execute the resulting string.

Hex decoding is validated before being treated as decoded text. Invalid or unexpected values are retained in their original representation rather than being guessed or silently rewritten.

Parsing failures are handled per event. A malformed audit record should not terminate the entire search; instead, the event can expose an `auditsearch_error` field describing the parsing problem.

AuditSearch does not make network requests or write outside Splunk-managed processing locations during normal operation.

---

# Installation

Download or package the `AuditSearch` directory and install it as a Splunk App.

The resulting structure should be:

```text
$SPLUNK_HOME/etc/apps/auditsearch/
```

For example:

```bash
tar -xzf AuditSearch.tar.gz -C $SPLUNK_HOME/etc/apps/
```

Then restart Splunk or reload the application.

No configuration is required on the source Linux servers.

AuditSearch does not need to be installed on the systems generating auditd logs.

---

# Requirements

AuditSearch requires:

* Splunk Enterprise
* Linux `auditd` events available in Splunk
* A Universal Forwarder or another existing Splunk ingestion mechanism capable of forwarding the audit log

The source server does **not** require:

* `ausearch`
* Python
* an AuditSearch installation
* a custom scripted input
* an AuditSearch-specific Add-on

---

# CLI Syntax Compatibility

AuditSearch supports `ausearch`-style bare options such as:

```text
-i
-k rootcmd
```

as well as Splunk-style argument forms:

```text
i=t
key=rootcmd
```

These forms can be mixed and used in any order.

For example, both of the following are valid:

```text
auditsearch -i -k rootcmd
```

and:

```text
auditsearch -k rootcmd -i
```

The command internally translates the `ausearch`-style syntax into the format expected by the Splunk search command framework.

This includes handling the two-token form:

```text
-k rootcmd
```

as well as:

```text
-k=rootcmd
```

and:

```text
key=rootcmd
```

This behavior is implemented explicitly because the default `splunklib.searchcommands` argument handling does not natively interpret bare `ausearch`-style flags in the required way.

---

# Examples

### Interpret all selected auditd events

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i
```

### Search for a specific audit key

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i -k rootcmd
```

### Search only EXECVE records

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i type=EXECVE
```

### Search activity for a specific login UID

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i auid=1000
```

### Combine filters

```spl
index=linux_audit sourcetype=auditd
| auditsearch -i -k rootcmd type=EXECVE auid=1000
| table _time host auid comm exe
```

### Recommended production pattern

```spl
index=linux_audit sourcetype=auditd
    host=server01
    type=EXECVE
    auid=1000
| auditsearch -i
| table _time host auid syscall comm exe PROCTITLE
```

The important principle is:

```text
Filter first → AuditSearch second
```

---

# What AuditSearch Does Not Do

AuditSearch intentionally does not:

* Modify indexed `_raw` events
* Rewrite auditd logs
* Transform auditd data into JSON at ingestion time
* Install anything on source Linux servers
* Execute decoded audit content
* Replace `auditd`
* Replace the Linux `ausearch` utility
* Require a Python runtime on monitored hosts
* Make network requests during event processing

Its purpose is narrower:

> **Bring useful `ausearch`-style interpretation and filtering into the Splunk search pipeline.**

---

# License

AuditSearch is licensed under the **Apache License, Version 2.0**.

Copyright © 2026 Hoomaan Haghparast.

You may obtain a copy of the License at:

https://www.apache.org/licenses/LICENSE-2.0

---

# Contributing

Contributions, bug reports, and improvements are welcome.

When contributing parsing or decoding logic, please preserve the project's core principles:

1. Do not modify the original audit event.
2. Prefer search-time processing.
3. Avoid source-side dependencies.
4. Treat audit data as untrusted input.
5. Keep parsing failures isolated to individual events.
6. Consider search performance when adding new interpretation logic.
