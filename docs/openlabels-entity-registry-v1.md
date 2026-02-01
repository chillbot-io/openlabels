# OpenLabels Entity Registry v1.0

**The Canonical Entity Type Reference for OpenLabels Scoring**

This document defines all entity types recognized by OpenLabels v1, their sensitivity weights, categories, and aliases. This registry represents the complete taxonomy for portable data sensitivity scoring.

---

## Weight Scale

| Weight | Sensitivity Level | Description |
|--------|-------------------|-------------|
| **10** | Critical | Immediate exploitation risk (credentials, complete identity) |
| **10** | Very High | Direct identifier enabling fraud/theft (SSN, passport) |
| **8** | High | Sensitive identifier or protected data (credit card, health) |
| **7** | High-Medium | Financial/healthcare IDs requiring protection |
| **6** | Medium-High | Semi-direct identifiers |
| **5** | Medium | Standard PII, moderate sensitivity |
| **4** | Low-Medium | Contact info, indirect identifiers |
| **3** | Low | Basic personal info, quasi-identifiers |
| **2** | Very Low | Minimal risk, contextual data |
| **1** | Minimal | Public or non-sensitive |

---

## Category: Direct Identifiers

Government-issued IDs that uniquely identify individuals.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `SSN` | **10** | US Social Security Number | social_security, ss |
| `PASSPORT` | **10** | Passport number (any country) | passport_number |
| `DRIVER_LICENSE` | **7** | Driver's license number | dl, dln, drivers_license |
| `STATE_ID` | **7** | State-issued ID card | id_card |
| `TAX_ID` | **8** | Tax identification number | tin, ein, itin |
| `AADHAAR` | **10** | India Aadhaar number | |
| `NHS_NUMBER` | **8** | UK NHS number | |
| `MEDICARE_ID` | **8** | US Medicare Beneficiary ID (MBI) | mbi |

---

## Category: Healthcare / PHI

Protected Health Information under HIPAA and similar regulations.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `MRN` | **8** | Medical Record Number | medical_record, chart_number |
| `HEALTH_PLAN_ID` | **8** | Insurance member/subscriber ID | member_id, subscriber_id |
| `NPI` | **7** | National Provider Identifier | |
| `DEA` | **7** | DEA registration number | dea_number |
| `DIAGNOSIS` | **8** | Medical diagnosis/condition | icd_code, condition |
| `MEDICATION` | **6** | Prescription/drug name | drug, prescription |
| `LAB_TEST` | **5** | Laboratory test name | |
| `ENCOUNTER_ID` | **5** | Healthcare encounter/visit ID | visit_id |
| `ACCESSION_ID` | **5** | Lab accession number | specimen_id |
| `PHARMACY_ID` | **5** | Pharmacy identifiers (RXBIN, RXPCN) | rxbin, rxpcn |
| `PATIENT_ACCOUNT` | **6** | Patient account number (context: "account", "acct") | account_number |
| `DATE_MEDICAL` | **3** | Date in medical context (admission, discharge, service) | admission_date, discharge_date, service_date |

---

## Category: Personal Information

Names and demographic identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `NAME` | **5** | Generic person name | full_name |
| `NAME_PATIENT` | **8** | Patient name (healthcare context) | patient |
| `NAME_PROVIDER` | **4** | Healthcare provider name | doctor, physician, hcw |
| `NAME_RELATIVE` | **7** | Family member/emergency contact | |
| `DATE_DOB` | **6** | Date of birth | dob, birthdate |
| `DATE` | **3** | Generic date | |
| `AGE` | **4** | Age in years/months | |
| `GENDER` | **2** | Gender/sex | sex |
| `RACE_ETHNICITY` | **4** | Race or ethnicity | |
| `RELIGION` | **4** | Religious affiliation | |
| `SEXUAL_ORIENTATION` | **5** | Sexual orientation | |
| `EMPLOYER` | **4** | Employer/company name | |
| `PROFESSION` | **3** | Job title/occupation | occupation |
| `EMPLOYEE_ID` | **5** | Employee identifier | staff_id |

---

## Category: Contact Information

Communication identifiers and physical location data.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `EMAIL` | **5** | Email address | email_address |
| `PHONE` | **4** | Phone/fax number | telephone, fax |
| `ADDRESS` | **5** | Physical/mailing address | street_address |
| `ZIP` | **3** | ZIP/postal code (see Safe Harbor note) | postal_code |
| `CITY` | **2** | City name | |
| `STATE` | **2** | State/province name | |
| `FACILITY` | **4** | Healthcare facility name | hospital, clinic |

> **Safe Harbor Note:** Per HIPAA Safe Harbor, ZIP codes must be truncated to first 3 digits if population <20,000. Dates of birth for individuals over 89 must be aggregated to year only. These rules should be enforced at the detection/redaction layer.

---

## Category: Financial

Payment instruments and financial identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `CREDIT_CARD` | **10** | Credit/debit card number | cc, card_number |
| `BANK_ACCOUNT` | **7** | Bank account number | account_number |
| `BANK_ROUTING` | **6** | ABA routing number | aba, routing_number |
| `IBAN` | **7** | International Bank Account Number | |
| `SWIFT_BIC` | **5** | SWIFT/BIC code | bic |

### Securities Identifiers

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `CUSIP` | **5** | CUSIP identifier | |
| `ISIN` | **5** | International Securities ID | |
| `SEDOL` | **5** | UK SEDOL code | |
| `FIGI` | **5** | Financial Instrument Global ID | |
| `LEI` | **5** | Legal Entity Identifier | |

### Cryptocurrency

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `BITCOIN_ADDRESS` | **8** | Bitcoin wallet address | btc_address |
| `ETHEREUM_ADDRESS` | **8** | Ethereum wallet address | eth_address |
| `CRYPTO_SEED_PHRASE` | **10** | BIP-39 mnemonic seed phrase | seed_phrase, mnemonic |
| `SOLANA_ADDRESS` | **8** | Solana wallet address | |
| `CARDANO_ADDRESS` | **8** | Cardano wallet address | |
| `LITECOIN_ADDRESS` | **8** | Litecoin wallet address | |
| `DOGECOIN_ADDRESS` | **8** | Dogecoin wallet address | |
| `XRP_ADDRESS` | **8** | XRP/Ripple address | |

---

## Category: Digital Identifiers

Network, device, and online identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `IP_ADDRESS` | **4** | IPv4 or IPv6 address | ip |
| `MAC_ADDRESS` | **4** | MAC address | |
| `URL` | **3** | Web URL | |
| `USERNAME` | **5** | Login username | user_id, login |
| `DEVICE_ID` | **5** | Device serial/identifier | serial_number |
| `IMEI` | **6** | Mobile device IMEI | |
| `VIN` | **5** | Vehicle Identification Number | |
| `BIOMETRIC_ID` | **8** | Biometric template/hash | fingerprint, retinal |
| `IMAGE_ID` | **4** | Photo/DICOM image identifier | |
| `TRACKING_NUMBER` | **2** | Shipping tracking number | |

---

## Category: Credentials & Secrets

Authentication tokens and sensitive credentials. **All credentials trigger critical risk.**

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `PASSWORD` | **10** | Password or passphrase | passwd, pwd |
| `API_KEY` | **10** | Generic API key | |
| `SECRET` | **10** | Generic secret/token | |
| `PRIVATE_KEY` | **10** | PEM-encoded private key | |
| `JWT` | **8** | JSON Web Token | |
| `BASIC_AUTH` | **10** | Basic authentication header | |
| `BEARER_TOKEN` | **8** | Bearer authentication token | |
| `DATABASE_URL` | **10** | Connection string with credentials | |

### Cloud Provider Credentials

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `AWS_ACCESS_KEY` | **10** | AWS access key ID | akia |
| `AWS_SECRET_KEY` | **10** | AWS secret access key | |
| `AWS_SESSION_TOKEN` | **10** | AWS temporary session token | |
| `AZURE_STORAGE_KEY` | **10** | Azure storage account key | |
| `AZURE_CONNECTION_STRING` | **10** | Azure connection string | |
| `AZURE_SAS_TOKEN` | **8** | Azure SAS token | |
| `GOOGLE_API_KEY` | **10** | Google API key | |
| `GOOGLE_OAUTH_ID` | **6** | Google OAuth client ID | |
| `GOOGLE_OAUTH_SECRET` | **10** | Google OAuth client secret | |
| `FIREBASE_KEY` | **10** | Firebase API key | |

### AI/ML Platform Keys (P0 - High Leak Risk)

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `OPENAI_API_KEY` | **10** | OpenAI API key | `sk-[a-zA-Z0-9]{48}` |
| `ANTHROPIC_API_KEY` | **10** | Anthropic/Claude API key | `sk-ant-api03-[a-zA-Z0-9\-_]{93}` |
| `HUGGINGFACE_TOKEN` | **10** | Hugging Face access token | `hf_[a-zA-Z0-9]{34}` |
| `COHERE_API_KEY` | **10** | Cohere API key | Context-based |
| `REPLICATE_TOKEN` | **10** | Replicate API token | `r8_[a-zA-Z0-9]{40}` |
| `STABILITY_API_KEY` | **10** | Stability AI key | Context-based |
| `MISTRAL_API_KEY` | **10** | Mistral AI key | Context-based |
| `TOGETHER_API_KEY` | **10** | Together AI key | Context-based |
| `GROQ_API_KEY` | **10** | Groq API key | `gsk_[a-zA-Z0-9]{52}` |

### Additional Cloud Providers

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `GCP_SERVICE_ACCOUNT` | **10** | GCP service account JSON | JSON with `"type": "service_account"` |
| `GCP_API_KEY` | **10** | GCP API key | Context-based |
| `DIGITALOCEAN_TOKEN` | **10** | DigitalOcean API token | `dop_v1_[a-f0-9]{64}` |
| `LINODE_TOKEN` | **10** | Linode API token | Context-based |
| `VULTR_API_KEY` | **10** | Vultr API key | Context-based |
| `ALIBABA_ACCESS_KEY` | **10** | Alibaba Cloud access key | `LTAI[a-zA-Z0-9]{12,20}` |
| `ORACLE_CLOUD_KEY` | **10** | Oracle Cloud API key | Context-based |
| `IBM_CLOUD_KEY` | **10** | IBM Cloud API key | Context-based |
| `CLOUDFLARE_API_KEY` | **10** | Cloudflare API key | Context-based |
| `CLOUDFLARE_TOKEN` | **10** | Cloudflare API token | Context-based |

### CI/CD Platform Tokens

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `CIRCLECI_TOKEN` | **10** | CircleCI API token | 40-char hex |
| `TRAVIS_TOKEN` | **10** | Travis CI token | Context-based |
| `JENKINS_TOKEN` | **10** | Jenkins API token | Context-based |
| `AZURE_DEVOPS_PAT` | **10** | Azure DevOps personal access token | 52-char base64 |
| `BITBUCKET_TOKEN` | **10** | Bitbucket app password/token | Context-based |
| `VERCEL_TOKEN` | **10** | Vercel API token | Context-based |
| `NETLIFY_TOKEN` | **10** | Netlify access token | Context-based |
| `RENDER_API_KEY` | **10** | Render API key | `rnd_[a-zA-Z0-9]+` |
| `RAILWAY_TOKEN` | **10** | Railway API token | Context-based |
| `FLY_TOKEN` | **10** | Fly.io API token | Context-based |

### Container Registry Tokens

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `DOCKER_HUB_TOKEN` | **10** | Docker Hub access token | `dckr_pat_[a-zA-Z0-9\-_]{56}` |
| `QUAY_TOKEN` | **10** | Quay.io robot token | Context-based |
| `ECR_TOKEN` | **10** | AWS ECR token | Context-based |
| `GCR_TOKEN` | **10** | Google Container Registry | Context-based |
| `ACR_TOKEN` | **10** | Azure Container Registry | Context-based |
| `HARBOR_TOKEN` | **10** | Harbor registry token | Context-based |

### Communication Platform Tokens

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `TELEGRAM_BOT_TOKEN` | **10** | Telegram bot token | `[0-9]{9,10}:[a-zA-Z0-9_-]{35}` |
| `TEAMS_WEBHOOK` | **8** | Microsoft Teams webhook | `https://.*\.webhook\.office\.com/.*` |
| `ZOOM_JWT` | **10** | Zoom JWT token | JWT with zoom context |
| `WEBEX_TOKEN` | **10** | Cisco Webex token | Context-based |
| `TWITCH_TOKEN` | **10** | Twitch OAuth token | `oauth:[a-z0-9]{30}` |
| `WHATSAPP_TOKEN` | **10** | WhatsApp Business API | Context-based |

### Payment Processor Tokens

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `PAYPAL_CLIENT_ID` | **8** | PayPal client ID | Context-based |
| `PAYPAL_SECRET` | **10** | PayPal client secret | Context-based |
| `BRAINTREE_TOKEN` | **10** | Braintree API token | Context-based |
| `PLAID_CLIENT_ID` | **8** | Plaid client ID | Context-based |
| `PLAID_SECRET` | **10** | Plaid secret | Context-based |
| `ADYEN_API_KEY` | **10** | Adyen API key | `AQE...` prefix |
| `KLARNA_TOKEN` | **10** | Klarna API token | Context-based |

### SaaS API Tokens

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `ATLASSIAN_TOKEN` | **10** | Atlassian/Jira/Confluence | Variable length |
| `NOTION_TOKEN` | **10** | Notion API token | `secret_[a-zA-Z0-9]{43}` |
| `AIRTABLE_KEY` | **10** | Airtable API key | `key[a-zA-Z0-9]{14}` or `pat...` |
| `LINEAR_TOKEN` | **10** | Linear API key | `lin_api_[a-zA-Z0-9]{40}` |
| `FIGMA_TOKEN` | **10** | Figma access token | `figd_[a-zA-Z0-9\-_]{40}` |
| `ASANA_TOKEN` | **10** | Asana personal access token | Context-based |
| `MONDAY_TOKEN` | **10** | Monday.com API token | Context-based |
| `ZENDESK_TOKEN` | **10** | Zendesk API token | Context-based |
| `INTERCOM_TOKEN` | **10** | Intercom access token | Context-based |
| `SEGMENT_KEY` | **10** | Segment write key | Context-based |
| `MIXPANEL_TOKEN` | **8** | Mixpanel project token | Context-based |
| `AMPLITUDE_KEY` | **8** | Amplitude API key | Context-based |
| `LAUNCHDARKLY_KEY` | **10** | LaunchDarkly SDK key | `sdk-[a-f0-9\-]{36}` |
| `SENTRY_DSN` | **8** | Sentry DSN | `https://[a-f0-9]+@...sentry.io/...` |
| `PAGERDUTY_KEY` | **10** | PagerDuty API key | `u+[a-zA-Z0-9]{18}` |
| `OPSGENIE_KEY` | **10** | Opsgenie API key | Context-based |
| `ROLLBAR_TOKEN` | **8** | Rollbar access token | Context-based |

### Database & Data Platform Tokens

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `SUPABASE_KEY` | **10** | Supabase API key | `sbp_[a-f0-9]{40}` |
| `PLANETSCALE_TOKEN` | **10** | PlanetScale token | `pscale_tkn_[a-zA-Z0-9\-_]{43}` |
| `NEON_TOKEN` | **10** | Neon database token | Context-based |
| `COCKROACHDB_TOKEN` | **10** | CockroachDB token | Context-based |
| `SNOWFLAKE_TOKEN` | **10** | Snowflake access token | Context-based |
| `DATABRICKS_TOKEN` | **10** | Databricks access token | `dapi[a-f0-9]{32}` |
| `ELASTICSEARCH_KEY` | **10** | Elasticsearch API key | Context-based |
| `ALGOLIA_KEY` | **10** | Algolia admin API key | 32-char hex |
| `REDIS_URL` | **10** | Redis connection URL | `redis://...` with password |
| `GRAFANA_TOKEN` | **10** | Grafana API token | `glc_[a-zA-Z0-9\-_]{32,}` |

### Email Service Tokens

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `POSTMARK_TOKEN` | **10** | Postmark server token | GUID format |
| `MAILGUN_KEY` | **10** | Mailgun API key | `key-[a-f0-9]{32}` |
| `RESEND_KEY` | **10** | Resend API key | `re_[a-zA-Z0-9]{32}` |
| `SPARKPOST_KEY` | **10** | SparkPost API key | Context-based |
| `SES_CREDENTIALS` | **10** | Amazon SES SMTP credentials | Context-based |

### SMS/Voice Service Tokens

| Entity Type | Weight | Description | Pattern Hint |
|-------------|--------|-------------|--------------|
| `VONAGE_KEY` | **10** | Vonage/Nexmo API key | Context-based |
| `VONAGE_SECRET` | **10** | Vonage/Nexmo API secret | Context-based |
| `PLIVO_AUTH_ID` | **8** | Plivo Auth ID | Context-based |
| `PLIVO_TOKEN` | **10** | Plivo Auth Token | Context-based |
| `MESSAGEBIRD_KEY` | **10** | MessageBird API key | Context-based |
| `BANDWIDTH_TOKEN` | **10** | Bandwidth API credentials | Context-based |

### Legacy Service Provider Tokens

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `GITHUB_TOKEN` | **10** | GitHub personal access token | ghp, gho, ghs, ghu |
| `GITLAB_TOKEN` | **10** | GitLab access token | glpat |
| `SLACK_TOKEN` | **10** | Slack bot/user token | xoxb, xoxp |
| `SLACK_WEBHOOK` | **8** | Slack webhook URL | |
| `DISCORD_TOKEN` | **10** | Discord bot token | |
| `DISCORD_WEBHOOK` | **7** | Discord webhook URL | |
| `STRIPE_KEY` | **10** | Stripe API key | sk_live, pk_live |
| `TWILIO_ACCOUNT_SID` | **7** | Twilio account SID | |
| `TWILIO_KEY` | **10** | Twilio API key | |
| `TWILIO_TOKEN` | **10** | Twilio auth token | |
| `SENDGRID_KEY` | **10** | SendGrid API key | |
| `MAILCHIMP_KEY` | **8** | Mailchimp API key | |
| `SQUARE_TOKEN` | **10** | Square access token | |
| `SQUARE_SECRET` | **10** | Square OAuth secret | |
| `SHOPIFY_TOKEN` | **10** | Shopify access token | |
| `SHOPIFY_KEY` | **8** | Shopify API key | |
| `SHOPIFY_SECRET` | **10** | Shopify shared secret | |
| `HEROKU_KEY` | **10** | Heroku API key | |
| `DATADOG_KEY` | **8** | Datadog API/app key | |
| `NEWRELIC_KEY` | **8** | New Relic API key | |
| `NPM_TOKEN` | **10** | NPM access token | |
| `PYPI_TOKEN` | **10** | PyPI API token | |
| `NUGET_KEY` | **8** | NuGet API key | |

---

## Category: Government & Classification

Security classifications and government identifiers.

### Classification Markings

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `CLASSIFICATION_LEVEL` | **8** | Classification level (TS, S, C, U) | |
| `CLASSIFICATION_MARKING` | **10** | Full classification line with caveats | |
| `SCI_MARKING` | **10** | Sensitive Compartmented Information | |
| `DISSEMINATION_CONTROL` | **8** | NOFORN, REL TO, ORCON, etc. | |
| `CLEARANCE_LEVEL` | **7** | Security clearance reference | |
| `ITAR_MARKING` | **8** | ITAR export control marking | |
| `EAR_MARKING` | **7** | EAR export control marking | |

### Government Entity Identifiers

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `CAGE_CODE` | **4** | Commercial and Government Entity Code | |
| `DUNS_NUMBER` | **4** | D-U-N-S number (deprecated) | |
| `UEI` | **4** | Unique Entity Identifier | |
| `DOD_CONTRACT` | **5** | DoD contract number | |
| `GSA_CONTRACT` | **4** | GSA schedule contract number | |

---

## Category: Education / FERPA

Student records and educational identifiers protected under FERPA.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `STUDENT_ID` | **7** | Student identification number | |
| `TRANSCRIPT` | **7** | Academic transcript/grades reference | |
| `ENROLLMENT_ID` | **6** | School enrollment identifier | |
| `FINANCIAL_AID_ID` | **7** | Financial aid application ID | fafsa_id |
| `SCHOOL_RECORD` | **6** | Educational record reference | |
| `GPA` | **5** | Grade point average | |
| `DISCIPLINARY_RECORD` | **7** | Student disciplinary information | |
| `IEP_ID` | **8** | Individualized Education Program | special_ed |
| `TEACHER_ID` | **5** | Teacher/instructor identifier | |
| `FERPA_DIRECTORY_INFO` | **4** | FERPA directory information | |

---

## Category: Legal

Court records, case identifiers, and legal professional IDs.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `CASE_NUMBER` | **6** | Court case/docket number | docket_number |
| `BAR_NUMBER` | **5** | Attorney bar registration | bar_id |
| `COURT_ID` | **4** | Court identifier | |
| `PACER_ID` | **6** | PACER login/account ID | |
| `INMATE_NUMBER` | **7** | Prison/jail inmate identifier | bop_number |
| `PROBATION_ID` | **7** | Probation/parole identifier | |
| `ARREST_RECORD` | **8** | Arrest record reference | booking_number |
| `WARRANT_NUMBER` | **7** | Warrant identifier | |
| `JUDGMENT_ID` | **6** | Court judgment reference | |
| `LEGAL_HOLD_ID` | **5** | Legal hold identifier | |

---

## Category: Vehicle & Transportation

Vehicle and transportation-related identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `VIN` | **5** | Vehicle Identification Number | |
| `LICENSE_PLATE` | **5** | Vehicle license plate number | plate_number |
| `REGISTRATION_NUMBER` | **5** | Vehicle registration | |
| `TITLE_NUMBER` | **5** | Vehicle title identifier | |
| `DOT_NUMBER` | **4** | USDOT carrier number | |
| `MC_NUMBER` | **4** | Motor carrier number | |
| `VESSEL_ID` | **5** | Boat/vessel identification | hin, hull_id |
| `AIRCRAFT_TAIL` | **5** | Aircraft tail number | n_number |
| `PILOT_LICENSE` | **6** | FAA pilot certificate number | |
| `CDL_NUMBER` | **7** | Commercial driver's license | |
| `TOLL_ACCOUNT` | **4** | Toll transponder account | ezpass, fastrak |

---

## Category: Immigration

Immigration and visa-related identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `A_NUMBER` | **10** | USCIS Alien Registration Number | alien_number |
| `VISA_NUMBER` | **8** | Visa foil number | |
| `I94_NUMBER` | **8** | I-94 arrival/departure number | |
| `GREEN_CARD_NUMBER` | **10** | Permanent resident card number | |
| `EAD_NUMBER` | **8** | Employment Authorization Document | work_permit |
| `SEVIS_ID` | **7** | Student visa SEVIS identifier | |
| `TRAVEL_DOCUMENT_NUMBER` | **8** | Refugee travel document | |
| `PETITION_NUMBER` | **6** | USCIS petition receipt number | |
| `NATURALIZATION_NUMBER` | **8** | Certificate of naturalization | |

---

## Category: Insurance

Insurance policy and claims identifiers (non-health).

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `POLICY_NUMBER` | **6** | Insurance policy number | |
| `CLAIM_NUMBER` | **6** | Insurance claim identifier | claim_id |
| `AGENT_NUMBER` | **4** | Insurance agent identifier | |
| `ADJUSTER_ID` | **4** | Claims adjuster identifier | |
| `NAIC_NUMBER` | **3** | NAIC company code | |
| `AUTO_POLICY_ID` | **6** | Auto insurance policy | |
| `HOME_POLICY_ID` | **6** | Homeowner's insurance policy | |
| `LIFE_POLICY_ID` | **7** | Life insurance policy | |
| `WORKERS_COMP_CLAIM` | **7** | Workers' compensation claim | |
| `DISABILITY_CLAIM_ID` | **7** | Disability insurance claim | |

---

## Category: Real Estate

Property and real estate identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `PARCEL_NUMBER` | **4** | Property parcel/APN number | apn |
| `DEED_NUMBER` | **5** | Deed recording number | |
| `MORTGAGE_ACCOUNT` | **7** | Mortgage loan number | loan_number |
| `ESCROW_NUMBER` | **6** | Escrow account identifier | |
| `MLS_NUMBER` | **3** | Multiple Listing Service ID | |
| `HOA_ACCOUNT` | **4** | Homeowner association account | |
| `TITLE_POLICY_NUMBER` | **5** | Title insurance policy | |
| `PROPERTY_TAX_ID` | **4** | Property tax account | |

---

## Category: Telecommunications

Mobile and telecommunications identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `IMEI` | **6** | Mobile device IMEI number | |
| `IMSI` | **7** | International Mobile Subscriber ID | |
| `ICCID` | **6** | SIM card identifier | sim_number |
| `MSISDN` | **6** | Mobile subscriber number | |
| `MEID` | **6** | Mobile Equipment Identifier | |
| `ESN` | **5** | Electronic Serial Number (legacy) | |
| `CARRIER_ACCOUNT` | **5** | Mobile carrier account number | |
| `VOIP_ACCOUNT` | **4** | VoIP service account | |
| `CALLING_CARD_NUMBER` | **5** | Calling card PIN | |
| `PORT_NUMBER` | **4** | Number porting authorization | |

---

## Category: Biometric & Genetic

Biometric templates and genetic identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `FINGERPRINT_TEMPLATE` | **10** | Fingerprint minutiae data | |
| `FACE_TEMPLATE` | **10** | Facial recognition template | face_encoding |
| `IRIS_TEMPLATE` | **10** | Iris scan template | |
| `VOICE_PRINT` | **8** | Voice biometric template | |
| `RETINAL_SCAN` | **10** | Retinal scan data | |
| `PALM_PRINT` | **8** | Palm print template | |
| `GAIT_SIGNATURE` | **7** | Gait analysis data | |
| `DNA_SEQUENCE` | **10** | DNA/genetic sequence data | |
| `GENETIC_MARKER` | **10** | Genetic marker/SNP data | snp |
| `ANCESTRY_ID` | **7** | Genetic ancestry service ID | |
| `BIOBANK_ID` | **8** | Biobank specimen identifier | |

---

## Category: Military

Military and defense-related identifiers.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `EDIPI` | **8** | DoD Electronic Data Interchange PI | |
| `SERVICE_NUMBER` | **8** | Military service number | |
| `MILITARY_ID` | **8** | Military ID card number | cac_number |
| `VA_CLAIM_NUMBER` | **7** | VA benefits claim identifier | |
| `DD214_NUMBER` | **8** | Discharge document number | |
| `MOS_CODE` | **3** | Military Occupational Specialty | |
| `UNIT_IDENTIFICATION` | **4** | Military unit identifier | uic |
| `SECURITY_BADGE_ID` | **6** | Facility security badge | |
| `SIPR_TOKEN` | **10** | SIPRNet token identifier | |
| `CAC_PIN` | **10** | CAC card PIN | |

---

## Category: Sensitive Files & Context

File patterns and contextual indicators of sensitive content.

| Entity Type | Weight | Description | Detection Pattern |
|-------------|--------|-------------|-------------------|
| `DOTENV_FILE` | **10** | Environment variable file | `.env`, `.env.local`, `.env.prod` |
| `KUBECONFIG` | **10** | Kubernetes configuration | `kubeconfig`, `.kube/config` |
| `SSH_CONFIG` | **8** | SSH configuration file | `.ssh/config`, `ssh_config` |
| `DOCKER_CONFIG` | **8** | Docker credentials | `.docker/config.json` |
| `NPM_RC` | **10** | NPM registry credentials | `.npmrc` with auth tokens |
| `PYPIRC` | **10** | PyPI credentials | `.pypirc` |
| `AWS_CREDENTIALS` | **10** | AWS credentials file | `.aws/credentials` |
| `NETRC` | **10** | FTP/HTTP credentials | `.netrc` |
| `HTPASSWD` | **8** | Apache password file | `.htpasswd` |
| `PGP_PRIVATE` | **10** | PGP private key file | `*.asc`, `secring.gpg` |
| `TERRAFORM_STATE` | **10** | Terraform state (may contain secrets) | `*.tfstate` |
| `ANSIBLE_VAULT` | **8** | Ansible encrypted content | Contains `$ANSIBLE_VAULT` |
| `CERTIFICATE_BUNDLE` | **7** | Certificate with private key | PFX, P12, combined PEM |
| `KEYSTORE` | **10** | Java keystore | `.jks`, `.keystore` |
| `WALLET_FILE` | **10** | Cryptocurrency wallet | `wallet.dat`, keystore JSON |
| `HISTORY_FILE` | **6** | Shell command history | `.bash_history`, `.zsh_history` |
| `SHADOW_FILE` | **10** | Unix shadow passwords | `/etc/shadow` format |

---

## Category: Temporal

Date and time values.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `DATE` | **3** | Generic date | |
| `DATE_DOB` | **6** | Date of birth | dob |
| `TIME` | **2** | Time value | |
| `DATETIME` | **3** | Combined date and time | timestamp |

---

## Category: Healthcare Context (Non-PII)

These entity types provide medical context but are not themselves PII. They inform risk scoring through co-occurrence rules but have minimal standalone weight.

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `DIAGNOSIS` | **8** | Medical diagnosis (PHI when linked) | |
| `MEDICATION` | **7** | Drug/medication name | |
| `LAB_TEST` | **5** | Laboratory test name | |
| `PAYER` | **2** | Insurance company name | |
| `ROOM` | **2** | Hospital room/bed number | |
| `MEDICAL_LICENSE` | **5** | Medical license number | |

---

## Category: Miscellaneous

| Entity Type | Weight | Description | Aliases |
|-------------|--------|-------------|---------|
| `UNIQUE_ID` | **5** | Generic unique identifier | |

---

## Co-occurrence Rules

Certain entity combinations create elevated risk beyond individual weights:

| Rule Name | Trigger Condition | Multiplier | Regulatory Basis |
|-----------|-------------------|------------|------------------|
| `hipaa_phi` | direct_id + health | **2.0×** | HIPAA PHI definition |
| `identity_theft` | direct_id + financial | **1.8×** | Fraud risk |
| `reidentification` | direct_id + quasi_id (3+) | **1.5×** | Sweeney research |
| `credential_exposure` | any credential + PII | **2.0×** | Immediate access risk |
| `bulk_quasi_id` | quasi_id (4+) alone | **1.7×** | Re-identification probability |
| `minor_data` | direct_id + age (<18) | **1.8×** | COPPA, enhanced protection |
| `classified_data` | classification_marking present | **2.5×** | National security |
| `ferpa_violation` | student_id + education_record | **1.8×** | FERPA privacy |
| `biometric_pii` | biometric + direct_id | **2.2×** | BIPA, biometric laws |
| `genetic_data` | genetic_marker OR dna_sequence | **2.0×** | GINA, genetic privacy |
| `immigration_status` | immigration_id + direct_id | **1.9×** | Immigration privacy |
| `military_sensitive` | military_id + classification | **2.5×** | OPSEC |
| `credential_file` | sensitive_file present | **1.5×** | Credential exposure |

### Category Mappings for Co-occurrence

```yaml
direct_id:
  - SSN
  - PASSPORT
  - DRIVER_LICENSE
  - TAX_ID
  - AADHAAR
  - MEDICARE_ID

health:
  - DIAGNOSIS
  - MEDICATION
  - MRN
  - NPI
  - DEA
  - HEALTH_PLAN_ID
  - LAB_TEST

financial:
  - CREDIT_CARD
  - BANK_ACCOUNT
  - IBAN
  - CRYPTO_SEED_PHRASE

quasi_id:
  - NAME
  - DATE_DOB
  - AGE
  - ZIP
  - GENDER
  - ADDRESS

credential:
  - PASSWORD
  - API_KEY
  - PRIVATE_KEY
  - AWS_ACCESS_KEY
  - AWS_SECRET_KEY
  - GITHUB_TOKEN
  - DATABASE_URL
  # (all credential types)

classification:
  - CLASSIFICATION_LEVEL
  - CLASSIFICATION_MARKING
  - SCI_MARKING
  - DISSEMINATION_CONTROL
  - ITAR_MARKING
  - EAR_MARKING

education:
  - STUDENT_ID
  - TRANSCRIPT
  - ENROLLMENT_ID
  - FINANCIAL_AID_ID
  - SCHOOL_RECORD
  - DISCIPLINARY_RECORD
  - IEP_ID

biometric:
  - FINGERPRINT_TEMPLATE
  - FACE_TEMPLATE
  - IRIS_TEMPLATE
  - VOICE_PRINT
  - RETINAL_SCAN
  - PALM_PRINT
  - DNA_SEQUENCE
  - GENETIC_MARKER

immigration:
  - A_NUMBER
  - VISA_NUMBER
  - I94_NUMBER
  - GREEN_CARD_NUMBER
  - EAD_NUMBER
  - SEVIS_ID
  - NATURALIZATION_NUMBER

military:
  - EDIPI
  - SERVICE_NUMBER
  - MILITARY_ID
  - DD214_NUMBER
  - SIPR_TOKEN
  - CAC_PIN

sensitive_file:
  - DOTENV_FILE
  - KUBECONFIG
  - AWS_CREDENTIALS
  - TERRAFORM_STATE
  - WALLET_FILE
  - SHADOW_FILE
  - PGP_PRIVATE
```

---

## Entity Count Summary

| Category | Count |
|----------|-------|
| Direct Identifiers | 8 |
| Healthcare / PHI | 10 |
| Personal Information | 15 |
| Contact Information | 7 |
| Financial | 17 |
| Digital Identifiers | 12 |
| Credentials & Secrets | 115 |
| Government & Classification | 13 |
| Education / FERPA | 10 |
| Legal | 10 |
| Vehicle & Transportation | 11 |
| Immigration | 9 |
| Insurance | 10 |
| Real Estate | 8 |
| Telecommunications | 10 |
| Biometric & Genetic | 11 |
| Military | 10 |
| Sensitive Files & Context | 17 |
| Temporal | 4 |
| Healthcare Context | 6 |
| **Total Unique Entity Types** | **~303** |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01 | Initial registry |
| 1.1 | 2026-01 | Added 115 credential/secret types (AI/ML, Cloud, CI/CD, SaaS, etc.) |
| 1.2 | 2026-01 | Added 96 entity types: Education/FERPA, Legal, Vehicle, Immigration, Insurance, Real Estate, Telecommunications, Biometric/Genetic, Military, Sensitive Files |

---

## Contributing New Entity Types

New entity types can be proposed via PR to the OpenLabels repository. Requirements:

1. **Justification** - Why is this entity type needed?
2. **Detection pattern** - Regex or algorithm for detection
3. **Weight rationale** - Why this sensitivity level?
4. **Test cases** - Positive and negative examples
5. **Category assignment** - Which category does it belong to?

Entity types should be added to the pattern modules and this registry simultaneously.

---

*This registry is the authoritative source for OpenLabels entity types. All adapters (Macie, Presidio, DLP, Purview) must map to these canonical types.*
