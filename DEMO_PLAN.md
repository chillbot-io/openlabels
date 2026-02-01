# OpenLabels Demo Plan

## The Core Message

**"One scan. Portable forever. Enforced everywhere."**

OpenLabels creates portable, durable, risk-informed labels that travel with files across systems, platforms, and clouds. Unlike traditional DLP that only works within one vendor's ecosystem, OpenLabels works everywhere.

---

## Demo Video: "The Label That Follows" (2-3 minutes)

### Scene 1: The Problem (15 sec)
- Quick montage: files moving between systems, clouds, emails
- Text overlay: "Your sensitive data moves. Your classifications don't."
- Show Macie finding PII in AWS, Purview finding it in Azure, but no connection

### Scene 2: Windows Desktop - Create the Label (30 sec)
- Open `customers.xlsx` in Excel (fake data with SSNs, credit cards)
- Launch OpenLabels GUI (Windows installer)
- Click "Scan" → watch progress
- Show the Label Preview panel:
  - `ol_7f3a9b2c4d5e` (Label ID)
  - Risk Score: 87 (CRITICAL)
  - Entities: SSN (47), CREDIT_CARD (12)
- Click "Embed Label" → "Label embedded successfully"
- **Key moment:** "This label is now INSIDE the file"

### Scene 3: Email Transit (10 sec)
- Drag file to email, send to self
- Animation showing file traveling across internet
- Text: "The label travels with the file"

### Scene 4: Mac/Linux - Read the Label (30 sec)
- Open terminal on Mac or Linux
- Download the attachment
- Run: `openlabels read customers.xlsx`
- Same label appears! Show JSON output:
```json
{
  "id": "ol_7f3a9b2c4d5e",
  "hash": "e3b0c44298fc",
  "labels": [{"t": "SSN", "n": 47}, {"t": "CREDIT_CARD", "n": 12}],
  "src": "openlabels:1.0.0",
  "ts": 1706745600
}
```
- **Key moment:** "Same label. Different continent. No cloud required."

### Scene 5: Cloud Enforcement (45 sec)
- Upload file to S3 bucket via AWS Console
- Show CloudWatch logs: Lambda triggered
- Lambda reads the embedded label
- Automatic actions:
  - S3 object tagged: `risk_tier=CRITICAL`, `has_pii=true`
  - Slack notification appears: "CRITICAL file uploaded: customers.xlsx"
  - S3 Block Public Access enabled
- **Key moment:** "The cloud enforces policy based on YOUR label"

### Scene 6: The Payoff (15 sec)
- Split screen: Windows GUI, Mac terminal, AWS Console
- All showing the same `ol_7f3a9b2c4d5e` label
- Text overlay: "One label. Everywhere."
- OpenLabels logo + GitHub link

---

## Live Demo Script (for ShowHN comments / live streams)

### Quick Demo (60 seconds)
```bash
# 1. Scan a file
openlabels scan ./test-data/

# 2. Show what was found
openlabels find --tier CRITICAL

# 3. Read embedded label from a file
openlabels read customers.xlsx

# 4. Show the portable JSON
cat customers.xlsx.openlabel.json
```

### Interactive Demo Points
1. **"Try it yourself"** - `pip install openlabels && openlabels scan ~/Downloads`
2. **"Check any file"** - `openlabels read suspicious_file.pdf`
3. **"Export for your tools"** - `openlabels report --format json > findings.json`

---

## Three Launch Paths

### Path 1: Windows Users (GUI)
```
Download → Double-click installer → Launch from Start Menu → Browse → Scan
```
- **Download link:** GitHub Releases page
- **No Python required**
- **Visual, point-and-click experience**

### Path 2: Linux/Mac Users (CLI)
```bash
pip install openlabels
openlabels scan /path/to/data
openlabels gui  # Optional GUI
```
- **One command install**
- **Works in scripts and pipelines**

### Path 3: Server/Enterprise (API)
```bash
# Docker
docker run -v /data:/data openlabels/openlabels scan /data

# Or as a service
openlabels serve --port 8080
```
- **Headless scanning**
- **REST API for integration**

---

## AWS Lambda Integration Demo

### Architecture
```
S3 Upload Event
      ↓
EventBridge Rule (*.xlsx, *.pdf, *.csv)
      ↓
Lambda Function
      ↓
   ┌──┴──┐
   │ Read │ OpenLabels from file
   └──┬──┘
      ↓
   ┌──┴──────────────────┐
   │ Actions:            │
   │ - Set S3 Object Tags│
   │ - SNS Alert         │
   │ - Block Public      │
   │ - Move to Quarantine│
   └─────────────────────┘
```

### What It Demonstrates
1. **Labels persist** - Lambda reads label that was created on Windows desktop
2. **Zero re-scanning** - No need to run Macie again, label has the info
3. **Policy enforcement** - Automatic actions based on risk tier
4. **Cost efficient** - ~$0.000004 per file vs Macie's $1+ per GB

### S3 Bucket Policy Example
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*",
    "Condition": {
      "StringEquals": {
        "s3:ExistingObjectTag/risk_tier": "CRITICAL"
      }
    }
  }]
}
```

---

## Key Differentiators to Highlight

| Feature | OpenLabels | Macie/Purview/DLP |
|---------|------------|-------------------|
| Labels travel with files | Yes | No |
| Cross-cloud | Yes | Vendor lock-in |
| Re-scan needed after move | No | Yes |
| Open format | Yes (JSON) | Proprietary |
| Cost | Free + ~$0.01/10K files | $1+/GB |
| Works offline | Yes | No |

---

## Sample Test Data

Create `test-data/` folder with:
- `customers.csv` - Fake names, SSNs, credit cards
- `employees.xlsx` - Fake employee records with SSNs
- `contracts.pdf` - PDF with fake bank account numbers
- `notes.txt` - Plain text with phone numbers, emails
- `clean_file.docx` - No sensitive data (shows MINIMAL tier)

Use faker library or https://generatedata.com/ for realistic fake data.

---

## ShowHN Post Draft

**Title:** OpenLabels - Portable risk labels that travel with your files

**Post:**
```
I built OpenLabels because I was frustrated that every cloud vendor's DLP
creates classifications that are trapped in their ecosystem.

Scan a file with AWS Macie → move it to Azure → Purview has no idea what
Macie found. You have to re-scan. The classification doesn't travel.

OpenLabels creates a portable JSON label that embeds directly in files
(PDF metadata, Office properties, image EXIF, or xattrs). When the file
moves, the label moves with it.

- Scan locally, enforce in the cloud
- One label format, works everywhere
- Open source, self-hosted, no vendor lock-in
- Integrates with existing tools via adapters

Demo video: [link]
GitHub: [link]

Try it: pip install openlabels && openlabels scan ~/Downloads

Would love feedback on the label format spec and what integrations
would be most useful.
```

---

## Technical Demo Prep Checklist

- [ ] Windows VM/machine with GUI installer tested
- [ ] Mac/Linux machine with pip install tested
- [ ] AWS account with test S3 bucket
- [ ] Lambda function deployed
- [ ] Test data files created (with fake PII)
- [ ] Screen recording software ready
- [ ] Demo script practiced 2-3 times

---

## Future Demo Ideas (Post-Launch)

1. **"Label Federation"** - Show Macie scan → OpenLabels adapter → portable label
2. **"The Audit Trail"** - File moves 5 times, label shows complete history
3. **"Cross-Cloud Policy"** - Same label enforced in AWS, Azure, and GCP
4. **"The Compliance Report"** - Generate SOC2/GDPR report from labels
