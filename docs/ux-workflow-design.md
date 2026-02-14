# OpenLabels UX Workflow Design

**Purpose:** Define every user-facing workflow as a sequence of decisions and screens _before_ writing UI code. This document is the single source of truth for interaction design.

---

## Table of Contents

1. [User Personas](#1-user-personas)
2. [Information Architecture](#2-information-architecture)
3. [Design Principles](#3-design-principles)
4. [Interaction Patterns](#4-interaction-patterns)
5. [Workflow 1: First-Time Setup](#5-workflow-1-first-time-setup)
6. [Workflow 2: Create Scan Target](#6-workflow-2-create-scan-target)
7. [Workflow 3: Run a Scan](#7-workflow-3-run-a-scan)
8. [Workflow 4: Browse & Triage Results](#8-workflow-4-browse--triage-results)
9. [Workflow 5: Apply Labels](#9-workflow-5-apply-labels)
10. [Workflow 6: Remediate a File](#10-workflow-6-remediate-a-file)
11. [Workflow 7: Schedule Recurring Scans](#11-workflow-7-schedule-recurring-scans)
12. [Workflow 8: Dashboard & Monitoring](#12-workflow-8-dashboard--monitoring)
13. [Workflow 9: Settings & Configuration](#13-workflow-9-settings--configuration)
14. [Page Inventory](#14-page-inventory)
15. [Component Pattern Library](#15-component-pattern-library)

---

## 1. User Personas

### Admin (Primary)
- **Role:** IT security admin or compliance officer
- **Goal:** Configure the system, scan file shares for PII, apply sensitivity labels, generate compliance reports
- **Frequency:** Daily for monitoring, weekly for configuration changes
- **Technical level:** Comfortable with Windows Server administration, understands file shares and Azure AD, but NOT a developer

### Viewer (Secondary)
- **Role:** Auditor, department manager, or executive
- **Goal:** View scan results, check compliance posture, export reports
- **Frequency:** Weekly or on-demand
- **Technical level:** Can navigate a web app, does not configure anything

### Key insight
Every screen must serve one of these two people. If a screen requires developer-level knowledge to use, the design is wrong.

---

## 2. Information Architecture

### Navigation Structure (Sidebar)

```
OpenLabels
├── Dashboard                    ← Landing page. "How are we doing?"
│
├── SCANNING ─────────────────── Section header
│   ├── Scan Targets             ← "What do we scan?"
│   ├── Scans                    ← "What has been scanned?"
│   └── Schedules                ← "When do we scan?"
│
├── FINDINGS ─────────────────── Section header
│   ├── Results                  ← "What did we find?"
│   ├── Labels                   ← "How are files classified?"
│   └── Remediation              ← "What did we fix?"
│
├── COMPLIANCE ───────────────── Section header
│   ├── Policies                 ← "What rules apply?"
│   └── Reports                  ← "Proof for auditors"
│
├── SYSTEM ───────────────────── Section header
│   ├── Monitoring               ← "Is everything healthy?"
│   ├── Activity Log              ← "Who did what?"
│   ├── Users                    ← "Who has access?"
│   └── Settings                 ← "System configuration"
```

### Navigation Design Rationale

The sidebar groups pages by the **question they answer**, not by technical entity. This means:

- A new admin can orient in under 30 seconds
- The hierarchy maps to the natural workflow: configure scanning → view findings → prove compliance
- "System" is at the bottom because it's infrequent (set-and-forget)

### Breadcrumb Pattern

Every page shows its location: `Dashboard > Scans > Scan #42`

---

## 3. Design Principles

### P1: Progressive Disclosure
Show the minimum viable information first. Reveal complexity through interaction.

**Example:** The Results table shows file path, risk tier, and score. Entity details are only visible when you click a row to expand or navigate to detail.

### P2: One Primary Action Per Screen
Every screen has ONE thing it wants you to do. Secondary actions exist but are visually subordinate.

**Example:** The Scan Targets list page → primary action is "Add Target" button. Editing/deleting are secondary (row actions menu).

### P3: Confirmation Before Destruction
Any action that changes data (delete, quarantine, label application) requires a confirmation dialog explaining what will happen.

### P4: Real-Time Feedback
Long-running operations (scans, label sync) show live progress, not just a spinner.

### P5: Empty States Are Onboarding
When a list is empty, don't show "No data." Show what to do next with a call-to-action.

**Example:** Empty scan targets page shows: "No scan targets configured. Add your first file share or SharePoint site to start scanning for sensitive data." [+ Add Scan Target]

---

## 4. Interaction Patterns

These are the reusable patterns every page draws from. Choosing the pattern first eliminates per-page UX guesswork.

### Pattern: Entity List Page
Used by: Targets, Scans, Schedules, Results, Labels, Users, Policies

```
┌──────────────────────────────────────────────────────────────┐
│  Page Title                              [+ Primary Action]  │
│                                                              │
│  ┌─ Filters ───────────────────────────────────────────────┐ │
│  │ [Status ▼]  [Risk Tier ▼]  [Date Range]  [Search...]   │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ Table ─────────────────────────────────────────────────┐ │
│  │ □  Name          Status    Risk     Date        ···     │ │
│  │ □  quarterly...  Complete  HIGH     2025-01-15  [···]   │ │
│  │ □  weekly-sh...  Running   —        2025-01-20  [···]   │ │
│  │ □  onedrive-...  Failed    —        2025-01-18  [···]   │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  Showing 1-25 of 142                    [< Prev] [Next >]    │
└──────────────────────────────────────────────────────────────┘
```

**Behaviors:**
- Click row → navigate to detail page (entire row is clickable, keyboard accessible via `role="link"`)
- `[···]` menu → secondary actions (edit, delete, retry, etc.)
- Checkbox column → batch actions (only if batch actions exist for this entity)
- Table columns are sortable (click header)
- Filters immediately apply (no "Apply" button)
- Empty state shows call-to-action

### Pattern: Entity Detail Page
Used by: Scan Detail, Result Detail, Target Detail

```
┌──────────────────────────────────────────────────────────────┐
│  ← Back to list         Entity Name           [Actions ▼]   │
│                                                              │
│  ┌─ Summary Card ──────────────────────────────────────────┐ │
│  │  Status: ● Running     Risk: ██ HIGH (72)               │ │
│  │  Created: Jan 15, 2025   By: admin@contoso.com          │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ Tabs ──────────────────────────────────────────────────┐ │
│  │  [Overview]  [Details]  [History]  [Related]             │ │
│  │                                                          │ │
│  │  (Tab content rendered here)                             │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

**Behaviors:**
- Back link returns to the list with scroll position preserved
- Actions dropdown for mutations (delete, retry, export)
- Tabs for organizing information without overwhelming
- Summary card is always visible (not inside a tab)

### Pattern: Create/Edit Form
Used by: New Target, New Schedule, Settings, Label Rules

```
┌──────────────────────────────────────────────────────────────┐
│  ← Back                Create Scan Target                    │
│                                                              │
│  ┌─ Step Indicator (if multi-step) ────────────────────────┐ │
│  │  ● Type  ─── ○ Configure  ─── ○ Review                 │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ Form Section ──────────────────────────────────────────┐ │
│  │  Section Label                                           │ │
│  │                                                          │ │
│  │  Field Label *                                           │ │
│  │  ┌──────────────────────────────────┐                    │ │
│  │  │ value                            │                    │ │
│  │  └──────────────────────────────────┘                    │ │
│  │  Helper text explaining the field                        │ │
│  │                                                          │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│             [Cancel]                  [Next →] / [Create]    │
└──────────────────────────────────────────────────────────────┘
```

**When to use a wizard (multi-step) vs single form:**
- **Wizard:** When the form has >6 fields, or when later fields depend on earlier choices (e.g., adapter type determines which fields appear)
- **Single form:** When there are ≤6 independent fields

**Behaviors:**
- Validation on blur (individual fields) + on submit (entire form)
- Error messages appear below the field, not in a toast
- Cancel returns to list without saving (confirm if form is dirty)
- "Create" button shows loading state, disables on submit

### Pattern: Confirmation Dialog
Used by: Delete, Quarantine, Lockdown, Label Apply

```
┌───────────────────────────────────────────┐
│  ⚠ Quarantine File?                      │
│                                           │
│  This will move the file to a             │
│  quarantine directory. Users will         │
│  lose access immediately.                 │
│                                           │
│  File: \\server\share\report.xlsx         │
│                                           │
│       [Cancel]    [Quarantine File]       │
└───────────────────────────────────────────┘
```

**Rules:**
- Destructive button uses red/danger styling
- Dialog title is the action as a question
- Body explains the consequence in plain language
- Shows the specific entity being affected
- Cancel is always available and is the default focus

### Pattern: Status Indicator
Consistent across all entities:

| State       | Visual                     | Color     |
|-------------|----------------------------|-----------|
| Pending     | ○ hollow circle            | Gray      |
| Running     | ● pulsing dot + spinner    | Blue      |
| Completed   | ✓ checkmark                | Green     |
| Failed      | ✕ x-mark                  | Red       |
| Cancelled   | — dash                     | Gray      |

### Pattern: Risk Tier Badge

| Tier      | Color       | Use            |
|-----------|-------------|----------------|
| CRITICAL  | Red         | Bright, urgent |
| HIGH      | Orange      | Warm warning   |
| MEDIUM    | Yellow      | Attention      |
| LOW       | Blue        | Informational  |
| MINIMAL   | Gray        | Deemphasized   |

---

## 5. Workflow 1: First-Time Setup

**Trigger:** Admin opens the app for the first time after installation.

### Flow

```
START
  │
  ▼
┌─────────────────────────────┐
│  Welcome Screen             │
│                             │
│  "Welcome to OpenLabels"    │
│  "Let's get you set up      │
│   in 3 steps."              │
│                             │
│  [Get Started →]            │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Step 1: Azure AD           │
│                             │
│  Tenant ID:  [________]     │
│  Client ID:  [________]     │
│  Secret:     [________]     │
│                             │
│  [Test Connection]          │
│                             │
│  ✓ Connected successfully   │
│                             │
│  [← Back]  [Next: Targets →]│
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Step 2: First Scan Target  │
│                             │
│  "What do you want to       │
│   scan first?"              │
│                             │
│  ┌──────────┐ ┌──────────┐  │
│  │ 📁       │ │ 🌐       │  │
│  │ File     │ │ Share-   │  │
│  │ Share    │ │ Point    │  │
│  └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐  │
│  │ ☁        │ │ Skip for │  │
│  │ OneDrive │ │ now      │  │
│  └──────────┘ └──────────┘  │
│                             │
│  (Selected: File Share)     │
│  Path: [\\server\share____] │
│                             │
│  [← Back]  [Next: Review →] │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Step 3: Review & Start     │
│                             │
│  Azure AD: ✓ Connected      │
│  Target: \\server\data       │
│                             │
│  "Ready to run your first   │
│   scan?"                    │
│                             │
│  [← Back] [Start Scan →]   │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Dashboard (with scan       │
│  running, showing progress) │
└─────────────────────────────┘
```

### Decisions Made
- **Why a wizard?** First-time setup has dependencies (Azure before targets) and is infrequent. A wizard prevents overwhelm.
- **"Skip for now" option** on target creation: Let admin explore the UI first if they aren't ready to scan.
- **"Test Connection" button** on Azure step: Validates credentials before proceeding. Prevents a broken setup from persisting.
- **Auto-navigate to Dashboard** with the first scan running: Immediate gratification. Admin sees the system working within minutes.

---

## 6. Workflow 2: Create Scan Target

**Trigger:** Admin clicks [+ Add Target] from the Scan Targets list page.

### Flow

```
Scan Targets List
       │
       │ Click [+ Add Target]
       ▼
┌──────────────────────────────────┐
│  Step 1: Choose Type             │
│                                  │
│  "What kind of resource do       │
│   you want to scan?"             │
│                                  │
│  ┌──────────────┐ ┌────────────┐ │
│  │ 📁 Windows   │ │ 🌐 Share-  │ │
│  │ File Share   │ │ Point      │ │
│  │              │ │ Online     │ │
│  │ UNC paths,   │ │ Sites &    │ │
│  │ mapped       │ │ document   │ │
│  │ drives       │ │ libraries  │ │
│  └──────────────┘ └────────────┘ │
│  ┌──────────────┐ ┌────────────┐ │
│  │ ☁ OneDrive   │ │ 🪣 Cloud   │ │
│  │ for Business │ │ Storage    │ │
│  │              │ │            │ │
│  │ User drives  │ │ S3, GCS,   │ │
│  │              │ │ Azure Blob │ │
│  └──────────────┘ └────────────┘ │
│                                  │
│  [Cancel]                        │
└──────────┬───────────────────────┘
           │
           │ Select "Windows File Share"
           ▼
┌──────────────────────────────────┐
│  Step 2: Configure               │
│                                  │
│  Target Name *                   │
│  ┌──────────────────────────┐    │
│  │ Finance Department Share │    │
│  └──────────────────────────┘    │
│  A friendly name for this target │
│                                  │
│  Path *                          │
│  ┌──────────────────────────┐    │
│  │ \\fileserver\finance     │    │
│  └──────────────────────────┘    │
│  UNC path or local directory     │
│                                  │
│  ┌─ Advanced (collapsed) ──────┐ │
│  │  ▶ File type filters        │ │
│  │  ▶ Exclude patterns         │ │
│  │  ▶ Max file size             │ │
│  └─────────────────────────────┘ │
│                                  │
│  [← Back]  [Validate & Create]  │
└──────────┬───────────────────────┘
           │
           │ Backend validates path
           ▼
      ┌────┴─────┐
      │ Valid?   │
      └────┬─────┘
       Yes │        No
           │         │
           ▼         ▼
  ┌────────────┐  ┌──────────────────┐
  │ Target     │  │ Inline error:    │
  │ created.   │  │ "Path not found  │
  │ Navigate   │  │  or not          │
  │ to list.   │  │  accessible."    │
  │            │  │                  │
  │ Toast:     │  │ Stay on form,    │
  │ "Target    │  │ focus path field │
  │  created"  │  └──────────────────┘
  └────────────┘
```

### Decisions Made

- **Card selection for type** (not a dropdown): The type choice is the most important decision and determines what fields appear. Cards with icons and descriptions make this scannable.
- **Progressive disclosure via "Advanced" section:** Most targets only need name + path. File type filters and excludes are edge cases — collapsed by default.
- **Validation happens on submit, not on navigation:** "Validate & Create" is a single action. This avoids a separate "Test" step that adds friction.
- **Two-step form, not three:** The type selection IS step 1. Configure IS step 2. No separate "Review" step — the form is short enough that a review step is redundant overhead.

### Adapter-Specific Fields

| Type           | Required Fields             | Optional Fields                          |
|----------------|-----------------------------|------------------------------------------|
| File Share     | Name, UNC Path              | Exclude patterns, max file size          |
| SharePoint     | Name, Site URL              | Document library filter, exclude folders |
| OneDrive       | Name, User email or "All"   | Folder filter                            |
| S3             | Name, Bucket, Region        | Prefix, IAM role ARN                     |
| GCS            | Name, Bucket                | Prefix, service account key              |
| Azure Blob     | Name, Container, Account    | Prefix, connection string                |

---

## 7. Workflow 3: Run a Scan

**Trigger:** Admin wants to scan a target for sensitive data.

### Entry Points (Multiple)

```
Entry A: From Scan Targets list
  → Row action [···] → "Scan Now"
  → Confirmation dialog → Scan created → Navigate to scan detail

Entry B: From Scans list
  → Click [+ New Scan]
  → Select target from dropdown → [Start Scan]
  → Navigate to scan detail

Entry C: From Dashboard
  → "Quick Scan" button (only shows if targets exist)
  → Select target from dropdown → [Start Scan]
  → Navigate to scan detail
```

### "New Scan" Dialog (Entry B & C)

```
┌───────────────────────────────────────────┐
│  New Scan                                 │
│                                           │
│  Target *                                 │
│  ┌─────────────────────────────────┐      │
│  │ Finance Department Share      ▼ │      │
│  └─────────────────────────────────┘      │
│                                           │
│  Scan Name (optional)                     │
│  ┌─────────────────────────────────┐      │
│  │ Q1 2025 Audit                   │      │
│  └─────────────────────────────────┘      │
│  Leave blank for auto-generated name      │
│                                           │
│       [Cancel]       [Start Scan]         │
└───────────────────────────────────────────┘
```

**Why a dialog, not a page?** Creating a scan only needs 1-2 fields. A full page is wasteful. A dialog keeps context (you launched it from the list, you return to the list or navigate to the scan).

### Scan Progress (Detail Page)

```
┌──────────────────────────────────────────────────────────────┐
│  ← Back to Scans        Q1 2025 Audit         [Cancel Scan] │
│                                                              │
│  ┌─ Progress ──────────────────────────────────────────────┐ │
│  │  ● Running                              42% complete    │ │
│  │  ████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    │ │
│  │                                                          │ │
│  │  Files scanned: 4,218 / 10,043                          │ │
│  │  Files with PII: 312                                    │ │
│  │  Elapsed: 12m 34s                                       │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ Live Findings (streams in via WebSocket) ──────────────┐ │
│  │                                                          │ │
│  │  \\server\finance\payroll\2024.xlsx     CRITICAL  92     │ │
│  │  \\server\finance\hr\employees.csv      HIGH      68     │ │
│  │  \\server\finance\invoices\q4.pdf       MEDIUM    35     │ │
│  │  (more rows appear as files are scanned...)              │ │
│  │                                                          │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Post-Completion State

```
┌──────────────────────────────────────────────────────────────┐
│  ← Back to Scans        Q1 2025 Audit         [Actions ▼]   │
│                                                              │
│  ┌─ Summary ───────────────────────────────────────────────┐ │
│  │  ✓ Completed  ·  Jan 15, 2025  ·  Duration: 28m 12s    │ │
│  │                                                          │ │
│  │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────────┐            │ │
│  │  │10,043│  │  312 │  │  47  │  │    18    │            │ │
│  │  │Files │  │With  │  │HIGH+ │  │Labels   │            │ │
│  │  │Scanned│  │PII   │  │Risk  │  │Applied  │            │ │
│  │  └──────┘  └──────┘  └──────┘  └──────────┘            │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ Tabs ──────────────────────────────────────────────────┐ │
│  │  [All Results (312)]  [Critical (12)]  [Unlabeled (47)] │ │
│  │                                                          │ │
│  │  (Results table with risk-tier filtering)                │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Decisions Made

- **Multiple entry points**: Scanning is the core action. It should be reachable from everywhere relevant (targets, scans list, dashboard), not hidden behind one path.
- **WebSocket live findings**: The "Live Findings" table streams results as they arrive. This gives the admin confidence the scan is working and lets them spot critical files early.
- **Post-completion tabs with pre-filtered views**: "Critical" and "Unlabeled" tabs surface the most actionable items without the admin having to configure filters manually.

---

## 8. Workflow 4: Browse & Triage Results

**Trigger:** Admin wants to review sensitive files found by scans.

### Flow

```
Results List Page
       │
       │  Filter: [Risk: HIGH+]  [Scan: Q1 Audit]  [Unlabeled only ☑]
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Results                                             [Export ▼]    │
│                                                                     │
│  Risk  │ File                          │ Entities    │ Label       │
│  ──────┼──────────────────────────────┼─────────────┼──────────── │
│  ██ 92 │ \\server\payroll\2024.xlsx   │ SSN(12)     │ None ⚠      │
│        │                              │ NAME(45)    │             │
│  ██ 78 │ \\server\hr\employees.csv    │ DOB(200)    │ Confidential│
│        │                              │ SSN(200)    │             │
│  ██ 65 │ \\server\legal\contract.pdf  │ NAME(8)     │ None ⚠      │
│        │                              │ ADDRESS(4)  │             │
│                                                                     │
│  Showing 1-25 of 312          [< Prev]  Page 1 of 13  [Next >]    │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         │ Click row
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  ← Back to Results        payroll/2024.xlsx      [Actions ▼]│
│                                                  │ Apply Label│
│  ┌─ Risk Summary ─────────────────────────────┐  │ Quarantine │
│  │  Risk Score: 92 (CRITICAL)                  │  │ Lockdown   │
│  │  Exposure: ORG_WIDE                         │  │ Export     │
│  │  Current Label: None                        │  └───────────┘
│  │  Recommended Label: Highly Confidential     │
│  └─────────────────────────────────────────────┘
│                                                              │
│  ┌─ Detected Entities ─────────────────────────────────────┐ │
│  │                                                          │ │
│  │  SSN (12 detections)                                     │ │
│  │  ├─ Sheet "Employees", row 2-13                          │ │
│  │  ├─ Confidence: 98% (checksum validated)                 │ │
│  │  └─ Detection tier: CHECKSUM (highest)                   │ │
│  │                                                          │ │
│  │  NAME (45 detections)                                    │ │
│  │  ├─ Sheet "Employees", column A                          │ │
│  │  ├─ Confidence: 82%                                      │ │
│  │  └─ Detection tier: ML                                   │ │
│  │                                                          │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ File Details ──────────────────────────────────────────┐ │
│  │  Path: \\server\finance\payroll\2024.xlsx                │ │
│  │  Size: 2.4 MB                                            │ │
│  │  Last Modified: Dec 20, 2024                             │ │
│  │  Owner: jsmith@contoso.com                               │ │
│  │  Permissions: Finance Team (read/write), All Staff (read)│ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ History ───────────────────────────────────────────────┐ │
│  │  Jan 15, 2025 - Scanned (Q1 Audit) — Score: 92         │ │
│  │  Dec 01, 2024 - Scanned (Monthly) — Score: 88           │ │
│  │  Nov 01, 2024 - First detected                          │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Triage Decision Tree

The admin's mental model when reviewing results:

```
For each HIGH/CRITICAL result:
  │
  ├── Is the file supposed to contain this data?
  │     ├── YES → Apply appropriate label → Done
  │     └── NO  → Should the file be restricted?
  │               ├── YES → Lockdown (restrict ACLs) → Apply label
  │               └── EXTREME → Quarantine (move to isolation) → Notify owner
  │
  └── Is the exposure level appropriate?
        ├── ORG_WIDE + CRITICAL → Definitely needs lockdown
        ├── INTERNAL + HIGH → Probably fine, just label it
        └── PRIVATE + any → Label only, exposure is already limited
```

### Decisions Made

- **Risk score is the primary sort:** Not file name, not date. The admin's job is to triage by severity.
- **"None" label with warning icon (⚠):** Unlabeled high-risk files are the primary action item. Make them impossible to miss.
- **Entity details are grouped and collapsible:** A file might have hundreds of detections. Group by entity type, show count, expand for details.
- **Actions dropdown on detail page:** Apply Label, Quarantine, and Lockdown are all accessible from one place, but behind a dropdown to prevent accidental clicks.

---

## 9. Workflow 5: Apply Labels

**Trigger:** Admin wants to classify a file with a sensitivity label.

### Two Modes

```
Mode A: Manual Label Application (single file)
─────────────────────────────────────────────

Result Detail Page → [Actions ▼] → "Apply Label"
       │
       ▼
┌───────────────────────────────────────────┐
│  Apply Sensitivity Label                  │
│                                           │
│  File: payroll/2024.xlsx                  │
│  Current Label: None                      │
│  Recommended: Highly Confidential         │
│                                           │
│  Select Label *                           │
│  ┌─────────────────────────────────┐      │
│  │ Highly Confidential (rec.)    ▼ │      │
│  └─────────────────────────────────┘      │
│                                           │
│  Labels available:                        │
│  ● Highly Confidential ← recommended     │
│  ○ Confidential                           │
│  ○ Internal                               │
│  ○ Public                                 │
│                                           │
│       [Cancel]       [Apply Label]        │
└───────────────────────────────────────────┘
       │
       ▼
  Toast: "Label applied to payroll/2024.xlsx"
  Result detail refreshes to show new label


Mode B: Auto-Label Rules (bulk, policy-based)
─────────────────────────────────────────────

Labels Page → [Label Rules] tab
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  Label Rules                                  [+ Add Rule]   │
│                                                              │
│  "Rules automatically apply labels to files based on         │
│   their risk tier or detected entity types."                 │
│                                                              │
│  ┌─ Rules Table ───────────────────────────────────────────┐ │
│  │  When                        Then Apply          Active │ │
│  │  ─────────────────────────── ──────────────────  ────── │ │
│  │  Risk tier = CRITICAL        Highly Confidential   ✓    │ │
│  │  Risk tier = HIGH            Confidential          ✓    │ │
│  │  Entity type contains SSN    Highly Confidential   ✓    │ │
│  │  Entity type contains DOB    Confidential          ○    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  Rules are evaluated top-to-bottom.                          │
│  First matching rule wins.                                   │
└──────────────────────────────────────────────────────────────┘
```

### Decisions Made

- **Recommended label is pre-selected:** The system already computed the right label. The admin just confirms. This makes the 80% case (accept recommendation) a single click.
- **Radio buttons, not a dropdown, for label selection:** There are typically 4-6 labels. Radio buttons show all options at once, making comparison easy.
- **Rules use simple "when/then" language:** Not "if risk_tier >= HIGH AND entity_type IN (...)". Plain language that the admin persona can understand.

---

## 10. Workflow 6: Remediate a File

**Trigger:** Admin identifies a high-risk file that needs immediate action.

### Flow

```
Result Detail Page → [Actions ▼]
       │
       ├── "Quarantine" (for extreme cases)
       │         │
       │         ▼
       │   ┌─────────────────────────────────────┐
       │   │  ⚠ Quarantine File?                 │
       │   │                                     │
       │   │  This will:                         │
       │   │  • Move the file to a quarantine    │
       │   │    directory                        │
       │   │  • Immediately revoke all access    │
       │   │  • Notify the file owner            │
       │   │                                     │
       │   │  This action can be reversed.       │
       │   │                                     │
       │   │  File: \\server\payroll\2024.xlsx   │
       │   │                                     │
       │   │    [Cancel]    [Quarantine File]     │
       │   └──────────────┬──────────────────────┘
       │                  │
       │                  ▼
       │         Result detail shows:
       │         Status: 🔒 Quarantined
       │         [Rollback] button appears
       │
       │
       └── "Lockdown" (restrict access)
                 │
                 ▼
           ┌─────────────────────────────────────┐
           │  🔒 Lock Down File?                 │
           │                                     │
           │  This will restrict access to        │
           │  only the following principals:      │
           │                                     │
           │  ☑ admin@contoso.com (owner)         │
           │  ☑ security-team@contoso.com         │
           │  □ finance-team@contoso.com          │
           │                                     │
           │  All other access will be removed.   │
           │                                     │
           │    [Cancel]    [Lock Down File]      │
           └──────────────┬──────────────────────┘
                          │
                          ▼
                 Result detail shows:
                 Status: 🔒 Locked Down
                 [Rollback] button appears
```

### Remediation History (on Remediation page)

```
┌──────────────────────────────────────────────────────────────┐
│  Remediation Actions                                         │
│                                                              │
│  ┌─ Active ────────────────────────────────────────────────┐ │
│  │  File                     Action      Date     Undo     │ │
│  │  payroll/2024.xlsx        Quarantine  Jan 15   [Rollback]│ │
│  │  hr/employees.csv         Lockdown    Jan 14   [Rollback]│ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ History ───────────────────────────────────────────────┐ │
│  │  File                     Action      Date     Status   │ │
│  │  legal/old-contracts.zip  Quarantine  Dec 10   Rolled   │ │
│  │                                                 back    │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Decisions Made

- **Separate "Quarantine" and "Lockdown"**: These are distinct severity levels. Quarantine = remove entirely. Lockdown = restrict who can access. Don't combine them.
- **Confirmation dialogs explain consequences in bullets**: "This will: move, revoke, notify." No ambiguity about what happens.
- **"This action can be reversed"**: Reduces anxiety. Admins are more likely to act on critical files if they know it's not permanent.
- **Rollback is always one click**: No confirmation dialog for rollback (it restores the original state, which is safe).

---

## 11. Workflow 7: Schedule Recurring Scans

**Trigger:** Admin wants scans to run automatically.

### Flow

```
Schedules List Page → [+ Create Schedule]
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  Create Schedule                                             │
│                                                              │
│  Target *                                                    │
│  ┌──────────────────────────────────────┐                    │
│  │ Finance Department Share            ▼ │                    │
│  └──────────────────────────────────────┘                    │
│                                                              │
│  Frequency *                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │  Daily   │ │  Weekly  │ │ Monthly  │ │ Custom   │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│                                                              │
│  (If Daily selected:)                                        │
│  Run at: [02:00 AM ▼]                                        │
│                                                              │
│  (If Weekly selected:)                                       │
│  Day: [Monday ▼]  Time: [02:00 AM ▼]                        │
│                                                              │
│  (If Custom selected:)                                       │
│  Cron expression: [0 2 * * * ________]                       │
│  "Runs at 2:00 AM every day"  ← human-readable preview      │
│                                                              │
│  ┌─ Options ───────────────────────────────────────────────┐ │
│  │  ☑ Delta scan (only scan new/changed files)             │ │
│  │  □ Auto-apply label rules after scan                    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  Next run: Monday, Jan 20, 2025 at 2:00 AM                  │
│                                                              │
│              [Cancel]              [Create Schedule]          │
└──────────────────────────────────────────────────────────────┘
```

### Decisions Made

- **Frequency presets before cron:** 90% of admins want daily/weekly/monthly. Only power users need raw cron. Presets first, "Custom" for cron.
- **Human-readable cron preview:** If using custom cron, show "Runs at 2:00 AM every day" below the input. Prevents cron syntax errors from causing unexpected behavior.
- **"Next run" preview:** Shows exactly when the schedule will fire. Removes ambiguity about timezone and cron interpretation.
- **Single form, not a wizard:** Only 3-4 fields. A wizard would be overkill.

---

## 12. Workflow 8: Dashboard & Monitoring

### Dashboard (Landing Page)

```
┌──────────────────────────────────────────────────────────────┐
│  Dashboard                               [Quick Scan ▼]      │
│                                                              │
│  ┌─ Summary Cards ─────────────────────────────────────────┐ │
│  │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐ │ │
│  │ │  142,819 │ │   3,412  │ │     47   │ │ 2 Running   │ │ │
│  │ │  Files   │ │  With    │ │  Critical│ │ Scans       │ │ │
│  │ │  Scanned │ │  PII     │ │  Risk    │ │ ● ●         │ │ │
│  │ └──────────┘ └──────────┘ └──────────┘ └─────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ Risk Distribution ──────┐  ┌─ Recent Scans ───────────┐ │
│  │                          │  │                           │ │
│  │  CRITICAL ███ 47         │  │  Q1 Audit    ✓ Complete   │ │
│  │  HIGH     ██████ 312     │  │  Weekly #12  ● Running    │ │
│  │  MEDIUM   █████████ 891  │  │  Weekly #11  ✓ Complete   │ │
│  │  LOW      ██████████ 1.2k│  │  Ad-hoc HR   ✕ Failed    │ │
│  │  MINIMAL  ███████████ 1k │  │                           │ │
│  │                          │  │  [View All Scans →]       │ │
│  └──────────────────────────┘  └───────────────────────────┘ │
│                                                              │
│  ┌─ 30-Day Trend ──────────────────────────────────────────┐ │
│  │       Files Scanned ── PII Found ··                      │ │
│  │  5k ┤    ╱╲                                              │ │
│  │     │   ╱  ╲   ╱╲                                        │ │
│  │  3k ┤──╱    ╲─╱  ╲──                                     │ │
│  │     │ ╱            ╲                                      │ │
│  │  1k ┤╱              ╲                                     │ │
│  │     └────────────────────────────────────                 │ │
│  │      Jan 1     Jan 8    Jan 15    Jan 22                  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─ Attention Required ────────────────────────────────────┐ │
│  │  ⚠ 47 CRITICAL files without labels                     │ │
│  │  ⚠ 12 files with ORG_WIDE exposure + HIGH risk          │ │
│  │  ℹ Label sync last run 3 days ago                        │ │
│  │                                                          │ │
│  │  [Review Critical Files →]                               │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Decisions Made

- **"Attention Required" section:** This is the most important part of the dashboard. It tells the admin what to do next, not just what the numbers are. Every card is actionable (links to the relevant filtered view).
- **Summary cards show counts, not percentages:** Admins think in "how many files need attention," not "what percentage of files are compliant."
- **Recent Scans panel:** Dashboard doubles as a quick status check for running scans.
- **"Quick Scan" button on dashboard:** The most common action should be accessible from the landing page.

---

## 13. Workflow 9: Settings & Configuration

### Settings Page Structure

```
┌──────────────────────────────────────────────────────────────┐
│  Settings                                                    │
│                                                              │
│  ┌─ Sidebar ──┐  ┌─ Content ──────────────────────────────┐ │
│  │            │  │                                         │ │
│  │  Azure AD  │  │  Azure AD Configuration                │ │
│  │  Scanning  │  │                                         │ │
│  │  Entities  │  │  Tenant ID                              │ │
│  │  Advanced  │  │  ┌──────────────────────────────────┐   │ │
│  │            │  │  │ a1b2c3d4-...                     │   │ │
│  │            │  │  └──────────────────────────────────┘   │ │
│  │            │  │                                         │ │
│  │            │  │  Client ID                              │ │
│  │            │  │  ┌──────────────────────────────────┐   │ │
│  │            │  │  │ e5f6g7h8-...                     │   │ │
│  │            │  │  └──────────────────────────────────┘   │ │
│  │            │  │                                         │ │
│  │            │  │  Client Secret                          │ │
│  │            │  │  ┌──────────────────────────────────┐   │ │
│  │            │  │  │ ••••••••••••                     │   │ │
│  │            │  │  └──────────────────────────────────┘   │ │
│  │            │  │                                         │ │
│  │            │  │  Status: ✓ Connected                    │ │
│  │            │  │  [Test Connection]    [Save Changes]    │ │
│  │            │  │                                         │ │
│  └────────────┘  └─────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Settings Sections

| Section   | Fields                                                                 |
|-----------|------------------------------------------------------------------------|
| Azure AD  | Tenant ID, Client ID, Client Secret, Test Connection                   |
| Scanning  | Max file size (MB), Concurrent files, Enable OCR, Enable ML           |
| Entities  | Checklist of 50+ entity types, grouped by category (Financial, Medical, Government IDs, etc.) with Select All / Deselect All per group |
| Advanced  | Fan-out enabled, Fan-out threshold, Max partitions, Pipeline parallelism |

### Decisions Made

- **Tabbed sidebar, not separate pages:** Settings are related and few. Separate pages (/settings/azure, /settings/scan) adds navigation overhead for no benefit.
- **"Save Changes" per section:** Not a global save. Each section saves independently. This prevents accidental changes when you only meant to update one thing.
- **"Test Connection" for Azure:** Immediate feedback before saving. Prevents broken configurations.
- **Entity types grouped with Select All:** 50+ checkboxes is unmanageable as a flat list. Grouping (Financial, Medical, Government IDs, Contact Info, Secrets) with section-level toggle makes it manageable.

---

## 14. Page Inventory

Complete list of pages with their pattern, primary action, and priority.

| Page                | Pattern       | Primary Action              | Priority |
|---------------------|---------------|-----------------------------|----------|
| Dashboard           | Custom        | Review attention items      | P0       |
| Scan Targets List   | Entity List   | Add Target                  | P0       |
| Create Target       | Wizard (2-step)| Configure & create          | P0       |
| Edit Target         | Form          | Save changes                | P1       |
| Scans List          | Entity List   | Start New Scan              | P0       |
| Scan Detail         | Entity Detail | Monitor progress / review   | P0       |
| Results List        | Entity List   | Triage (click → detail)     | P0       |
| Result Detail       | Entity Detail | Apply Label / Remediate     | P0       |
| Labels List         | Entity List   | Sync from M365              | P1       |
| Label Rules         | Entity List   | Add Rule                    | P1       |
| Schedules List      | Entity List   | Create Schedule             | P1       |
| Create Schedule     | Form          | Create                      | P1       |
| Remediation         | Entity List   | Rollback / review           | P1       |
| Policies List       | Entity List   | Create Policy               | P2       |
| Reports             | Custom        | Generate Report             | P2       |
| Monitoring          | Entity List   | View job health             | P2       |
| Activity Log        | Entity List   | Search / filter events      | P2       |
| Users               | Entity List   | Add User                    | P2       |
| Settings            | Tabbed Form   | Save per section            | P1       |
| First-Time Setup    | Wizard (3-step)| Complete setup             | P0       |
| Login               | Custom        | Authenticate                | P0       |

### Build Order (recommended)

1. **Phase 1 (Core loop):** Login → First-Time Setup → Dashboard → Scan Targets + Create → Scans + Detail → Results + Detail
2. **Phase 2 (Actions):** Labels + Rules → Remediation → Settings
3. **Phase 3 (Automation):** Schedules → Policies → Reports
4. **Phase 4 (Admin):** Users → Activity Log → Monitoring

---

## 15. Component Pattern Library

Reusable components that every page draws from. Build these ONCE, then assemble pages.

### Layout Components

| Component        | Description                                           |
|------------------|-------------------------------------------------------|
| `AppShell`       | Sidebar + header + main content area                  |
| `PageHeader`     | Title + primary action button + breadcrumbs           |
| `Section`        | Titled content block with optional collapse           |

### Data Display

| Component         | Description                                          |
|-------------------|------------------------------------------------------|
| `DataTable`       | Sortable, filterable table with pagination            |
| `FilterBar`       | Row of filter controls (dropdowns, search, toggles)   |
| `EmptyState`      | Illustration + message + CTA when list is empty       |
| `StatusBadge`     | Colored dot + text (Pending, Running, Complete, etc.) |
| `RiskBadge`       | Colored badge for risk tier (CRITICAL, HIGH, etc.)    |
| `StatCard`        | Number + label card for dashboard summaries           |
| `Timeline`        | Vertical timeline for history/audit entries           |
| `TrendChart`      | Line chart for 30-day trends                          |

### Forms

| Component         | Description                                          |
|-------------------|------------------------------------------------------|
| `FormField`       | Label + input + helper text + error message           |
| `CardSelect`      | Grid of selectable cards (for type selection)         |
| `StepIndicator`   | Horizontal step progress (for wizards)                |
| `CronInput`       | Cron expression input with human-readable preview     |

### Feedback

| Component            | Description                                       |
|----------------------|---------------------------------------------------|
| `ConfirmDialog`      | Modal with consequence description + action button |
| `Toast`              | Temporary success/error notification               |
| `ProgressBar`        | Determinate progress with percentage               |
| `LoadingState`       | Skeleton screens while data loads                  |

### Navigation

| Component         | Description                                          |
|-------------------|------------------------------------------------------|
| `Sidebar`         | Collapsible nav with section headers                  |
| `Breadcrumbs`     | Location indicator with back navigation               |
| `Tabs`            | Horizontal tab bar for detail page sections            |

---

## Appendix: What NOT to Build

Things that seem useful but add complexity without proportional value:

- **File explorer / tree view:** The admin doesn't browse files in the app. They know their file shares. Results are the primary navigation path, not folder trees.
- **Drag-and-drop anything:** No rearranging, no drag-to-quarantine. Click actions are sufficient and more accessible.
- **Real-time collaboration:** Single admin at a time is the expected usage. No presence indicators or conflict resolution needed.
- **Custom dashboard widgets:** One good default dashboard layout beats a configurable one that nobody configures.
- **Inline editing in tables:** Always navigate to a detail page or open a dialog. Inline editing is fragile and hard to make accessible.
