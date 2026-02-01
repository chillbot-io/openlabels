# Exposure Level Permission Mappings

This document details how OpenLabels maps platform-specific permissions to normalized exposure levels.

## Exposure Levels

| Level       | Value | Description                                          |
|-------------|-------|------------------------------------------------------|
| PRIVATE     | 0     | Only owner or explicitly named principals            |
| INTERNAL    | 1     | Same organization/tenant, requires authentication    |
| ORG_WIDE    | 2     | Overly broad access (all authenticated, large groups)|
| PUBLIC      | 3     | Anonymous access, no authentication required         |

## AWS S3 Mappings

| S3 Permission                              | Level       |
|--------------------------------------------|-------------|
| ACL: private                               | PRIVATE     |
| ACL: bucket-owner-full-control             | PRIVATE     |
| ACL: bucket-owner-read                     | PRIVATE     |
| ACL: aws-exec-read                         | INTERNAL    |
| ACL: log-delivery-write                    | INTERNAL    |
| ACL: authenticated-read                    | ORG_WIDE    |
| ACL: public-read                           | PUBLIC      |
| ACL: public-read-write                     | PUBLIC      |
| Policy: Principal="*" (no Condition)       | PUBLIC      |
| Policy: Principal="*" + aws:SourceArn      | INTERNAL    |
| Cross-account access                       | ORG_WIDE    |
| Website hosting enabled                    | PUBLIC      |
| Public Access Block: all enabled           | blocks→PRIV |

## GCP GCS Mappings

| GCS Permission                             | Level       |
|--------------------------------------------|-------------|
| IAM: specific user/serviceAccount          | PRIVATE     |
| IAM: projectViewer/Editor/Owner            | INTERNAL    |
| IAM: group:*@domain.com                    | INTERNAL    |
| IAM: domain:domain.com                     | INTERNAL    |
| IAM: allAuthenticatedUsers                 | ORG_WIDE    |
| IAM: allUsers                              | PUBLIC      |
| ACL entity: user-* / group-*               | PRIVATE     |
| ACL entity: project-*                      | INTERNAL    |
| ACL entity: allAuthenticatedUsers          | ORG_WIDE    |
| ACL entity: allUsers                       | PUBLIC      |
| Cross-project service account access       | ORG_WIDE    |
| publicAccessPrevention: enforced           | blocks→PRIV |

## Azure Blob Mappings

| Azure Blob Permission                      | Level       |
|--------------------------------------------|-------------|
| access_level: private                      | PRIVATE     |
| RBAC: specific user/service principal      | PRIVATE     |
| RBAC: Owner/Contributor (resource scope)   | INTERNAL    |
| access_level: blob (blob-level anonymous)  | ORG_WIDE    |
| SAS token: limited scope + expiry          | INTERNAL    |
| SAS token: broad scope / no expiry         | ORG_WIDE    |
| access_level: container                    | PUBLIC      |
| SAS token: publicly shared                 | PUBLIC      |
| Cross-tenant access                        | ORG_WIDE    |
| Network rules: default=Allow               | ORG_WIDE    |
| Network rules: default=Deny + VNet rules   | INTERNAL    |
| Private endpoint only                      | PRIVATE     |

## NTFS (Windows) Mappings

| NTFS Permission                            | Level       |
|--------------------------------------------|-------------|
| Owner only                                 | PRIVATE     |
| Specific user/group ACE                    | PRIVATE     |
| CREATOR OWNER                              | PRIVATE     |
| Domain Admins                              | INTERNAL    |
| Domain Users                               | INTERNAL    |
| Authenticated Users (domain)               | INTERNAL    |
| BUILTIN\Users                              | ORG_WIDE    |
| Everyone (authenticated context)           | ORG_WIDE    |
| Anonymous Logon                            | PUBLIC      |
| Everyone (+ anonymous enabled)             | PUBLIC      |
| NULL SID                                   | PUBLIC      |
| Network share: Everyone Full Control       | PUBLIC      |
| Inherited broad permissions                | ORG_WIDE    |

## NFS Mappings

| NFS Permission                             | Level       |
|--------------------------------------------|-------------|
| root_squash + specific UID/GID             | PRIVATE     |
| Single host export (/path host)            | PRIVATE     |
| Kerberos auth (sec=krb5/krb5i/krb5p)       | INTERNAL    |
| Subnet export (/path 10.0.0.0/24)          | INTERNAL    |
| all_squash + anonuid mapping               | INTERNAL    |
| Large subnet (/16 or broader)              | ORG_WIDE    |
| no_root_squash                             | ORG_WIDE    |
| sec=sys (AUTH_SYS, UID trust)              | ORG_WIDE    |
| Export: * (all hosts)                      | PUBLIC      |
| insecure option (non-privileged ports)     | PUBLIC      |
| World-readable (mode 755/644) + * export   | PUBLIC      |
| no_auth_nlm                                | PUBLIC      |

## M365 (SharePoint/OneDrive) Mappings

| M365 Permission                            | Level       |
|--------------------------------------------|-------------|
| Specific users (direct permission)         | PRIVATE     |
| "Only people with existing access"         | PRIVATE     |
| Private channel membership                 | PRIVATE     |
| Security group (scoped)                    | INTERNAL    |
| "People in your organization" link         | INTERNAL    |
| M365 Group / Team membership               | INTERNAL    |
| Site collection scoped                     | INTERNAL    |
| "People in &lt;org&gt; with the link"      | ORG_WIDE    |
| "Anyone in org" (all employees)            | ORG_WIDE    |
| External sharing: specific guests          | ORG_WIDE    |
| External sharing: existing guests          | ORG_WIDE    |
| "Anyone with the link" (sign-in req)       | ORG_WIDE    |
| "Anyone with the link" (no sign-in)        | PUBLIC      |
| Anonymous guest links                      | PUBLIC      |
| Public site / Public CDN                   | PUBLIC      |
| Forms: anyone can respond                  | PUBLIC      |
