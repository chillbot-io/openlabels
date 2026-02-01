"""Command-line interface for ScrubIQ.

API Key Authentication:
- Set SCRUBIQ_API_KEY environment variable, or
- Use `scrubiq keys create` to generate a new key

Examples:
    # Create first API key (interactive, no auth needed)
    scrubiq keys create --name "my-first-key"

    # Set the key in environment
    export SCRUBIQ_API_KEY="sk-..."

    # Use ScrubIQ
    echo "Patient John Smith SSN 123-45-6789" | scrubiq redact
"""

import os
import sys
import time
import argparse
from datetime import datetime
from pathlib import Path

from .config import Config
from .core import ScrubIQ
from .services import APIKeyService
from .storage import Database
from .types import PrivacyMode


def get_config(args) -> Config:
    """Get configuration with optional data dir override."""
    config = Config()
    if hasattr(args, 'data_dir') and args.data_dir:
        config.data_dir = Path(args.data_dir).expanduser()
    return config


def get_api_key() -> str:
    """Get API key from environment."""
    key = os.environ.get("SCRUBIQ_API_KEY")
    if not key:
        print(
            "Error: SCRUBIQ_API_KEY environment variable not set.\n"
            "Create a key with: scrubiq keys create --name 'my-key'\n"
            "Then set: export SCRUBIQ_API_KEY='sk-...'",
            file=sys.stderr
        )
        sys.exit(1)
    return key


def get_scrubiq_with_key(config: Config, api_key: str) -> ScrubIQ:
    """Create and unlock ScrubIQ instance using API key."""
    cr = ScrubIQ(config)

    # Initialize API key service
    service = APIKeyService(cr._db)

    # Validate key
    metadata = service.validate_key(api_key)
    if metadata is None:
        print("Error: Invalid API key", file=sys.stderr)
        sys.exit(1)

    # Derive encryption key and unlock
    encryption_key = service.derive_encryption_key(api_key)
    try:
        # SECURITY FIX: Use full 64-char hex (32 bytes) instead of truncated 32-char (16 bytes)
        # Truncation was reducing AES-256 to AES-128 effective strength
        cr.unlock(encryption_key.hex())
    except Exception as e:
        print(f"Error: Failed to unlock: {e}", file=sys.stderr)
        sys.exit(1)

    return cr


# ============================================================================
# KEY MANAGEMENT COMMANDS
# ============================================================================


def cmd_keys_create(args):
    """Create a new API key."""
    config = get_config(args)
    config.ensure_directories()

    # Create database connection
    db = Database(config.db_path)
    db.connect()

    service = APIKeyService(db)

    # Check if keys exist
    has_keys = service.has_any_keys()

    if has_keys and not args.force:
        # Require existing key for authentication
        existing_key = os.environ.get("SCRUBIQ_API_KEY")
        if not existing_key:
            print(
                "Error: API keys already exist. Authenticate with SCRUBIQ_API_KEY "
                "or use --force for initial setup.",
                file=sys.stderr
            )
            db.close()
            sys.exit(1)

        # Validate existing key has admin permission
        meta = service.validate_key(existing_key)
        if meta is None:
            print("Error: Invalid API key", file=sys.stderr)
            db.close()
            sys.exit(1)
        if "admin" not in meta.permissions:
            print("Error: Admin permission required to create new keys", file=sys.stderr)
            db.close()
            sys.exit(1)

    # Parse permissions
    permissions = None
    if args.permissions:
        permissions = [p.strip() for p in args.permissions.split(",")]
        valid = {"redact", "restore", "chat", "admin", "files"}
        invalid = set(permissions) - valid
        if invalid:
            print(f"Error: Invalid permissions: {invalid}. Valid: {valid}", file=sys.stderr)
            db.close()
            sys.exit(1)

    # First key gets admin permissions by default
    if not has_keys and permissions is None:
        permissions = ["redact", "restore", "chat", "admin", "files"]
        print("Note: First key granted full permissions (including admin)")

    # Create the key
    full_key, metadata = service.create_key(
        name=args.name,
        rate_limit=args.rate_limit,
        permissions=permissions,
    )

    db.close()

    print("\n" + "=" * 60)
    print("API KEY CREATED - SAVE THIS KEY!")
    print("=" * 60)
    print(f"\nKey:        {full_key}")
    print(f"Name:       {metadata.name}")
    print(f"Prefix:     {metadata.key_prefix}")
    print(f"Rate Limit: {metadata.rate_limit} req/min")
    print(f"Permissions: {', '.join(metadata.permissions)}")
    print("\n" + "=" * 60)
    print("WARNING: This key will only be shown ONCE!")
    print("Store it securely. Lost keys cannot be recovered.")
    print("=" * 60)
    print(f"\nTo use this key:")
    print(f"  export SCRUBIQ_API_KEY='{full_key}'")


def cmd_keys_list(args):
    """List all API keys."""
    config = get_config(args)
    api_key = get_api_key()

    db = Database(config.db_path)
    db.connect()

    service = APIKeyService(db)

    # Validate key has admin permission
    meta = service.validate_key(api_key)
    if meta is None:
        print("Error: Invalid API key", file=sys.stderr)
        db.close()
        sys.exit(1)
    if "admin" not in meta.permissions:
        print("Error: Admin permission required to list keys", file=sys.stderr)
        db.close()
        sys.exit(1)

    keys = service.list_keys(include_revoked=args.all)
    db.close()

    if not keys:
        print("No API keys found.")
        return

    print(f"\n{'Prefix':<12} {'Name':<20} {'Rate':<8} {'Permissions':<25} {'Last Used':<20} {'Status'}")
    print("-" * 110)

    for k in keys:
        last_used = datetime.fromtimestamp(k.last_used_at).strftime("%Y-%m-%d %H:%M") if k.last_used_at else "never"
        status = "revoked" if k.is_revoked else "active"
        perms = ", ".join(k.permissions[:3])
        if len(k.permissions) > 3:
            perms += f" +{len(k.permissions) - 3}"

        print(f"{k.key_prefix:<12} {k.name[:20]:<20} {k.rate_limit:<8} {perms:<25} {last_used:<20} {status}")


def cmd_keys_revoke(args):
    """Revoke an API key."""
    config = get_config(args)
    api_key = get_api_key()

    db = Database(config.db_path)
    db.connect()

    service = APIKeyService(db)

    # Validate key has admin permission
    meta = service.validate_key(api_key)
    if meta is None:
        print("Error: Invalid API key", file=sys.stderr)
        db.close()
        sys.exit(1)
    if "admin" not in meta.permissions:
        print("Error: Admin permission required to revoke keys", file=sys.stderr)
        db.close()
        sys.exit(1)

    # Don't allow revoking own key
    if api_key.startswith(args.prefix):
        print("Error: Cannot revoke your own key", file=sys.stderr)
        db.close()
        sys.exit(1)

    success = service.revoke_key(args.prefix)
    db.close()

    if success:
        print(f"Key revoked: {args.prefix}")
    else:
        print(f"Error: Key not found or already revoked: {args.prefix}", file=sys.stderr)
        sys.exit(1)


# ============================================================================
# MAIN COMMANDS
# ============================================================================


def cmd_redact(args):
    """Redact text from command line or stdin."""
    config = get_config(args)
    api_key = get_api_key()

    with get_scrubiq_with_key(config, api_key) as cr:
        if args.text:
            text = args.text
        else:
            text = sys.stdin.read()

        result = cr.redact(text)
        print(result.redacted)

        if args.verbose:
            print(f"\n--- {len(result.spans)} spans detected ---", file=sys.stderr)
            for span in result.spans:
                print(f"  {span.entity_type}: [REDACTED] ({span.confidence:.2f})", file=sys.stderr)


def cmd_restore(args):
    """Restore tokens in text."""
    config = get_config(args)
    api_key = get_api_key()

    mode = PrivacyMode.RESEARCH
    if args.safe_harbor:
        mode = PrivacyMode.SAFE_HARBOR

    with get_scrubiq_with_key(config, api_key) as cr:
        if args.text:
            text = args.text
        else:
            text = sys.stdin.read()

        result = cr.restore(text, mode=mode)
        print(result.restored)


def cmd_tokens(args):
    """List tokens in session."""
    config = get_config(args)
    api_key = get_api_key()

    with get_scrubiq_with_key(config, api_key) as cr:
        tokens = cr.get_tokens()

        if not tokens:
            print("No tokens stored.")
            return

        for t in tokens:
            print(f"{t['token']}: {t['safe_harbor']} ({t['type']})")


def cmd_audit(args):
    """Show audit log."""
    config = get_config(args)
    api_key = get_api_key()

    with get_scrubiq_with_key(config, api_key) as cr:
        if args.verify:
            valid, error = cr.verify_audit_chain()
            if valid:
                print("Audit chain: VALID")
            else:
                print(f"Audit chain: INVALID - {error}")
            return

        entries = cr.get_audit_entries(limit=args.limit)

        for e in entries:
            print(f"[{e['sequence']}] {e['timestamp']} {e['event']}")
            if args.verbose:
                for k, v in e['data'].items():
                    print(f"    {k}: {v}")


def cmd_bench(args):
    """Run benchmark."""
    config = get_config(args)
    api_key = get_api_key()

    test_texts = [
        "Patient John Smith, SSN 123-45-6789, DOB 01/15/1980",
        "Call Dr. Jane Doe at (555) 123-4567 or email jane.doe@hospital.org",
        "MRN: 12345678, Medicare: 1AB2345CD67",
        "Address: 123 Main Street, Springfield, IL 62701",
        "Credit card: 4111-1111-1111-1111, NPI: 1234567893",
    ]

    with get_scrubiq_with_key(config, api_key) as cr:
        # Warmup
        for t in test_texts:
            cr.redact(t)

        # Benchmark
        n_iterations = args.iterations
        start = time.time()

        for _ in range(n_iterations):
            for t in test_texts:
                cr.redact(t)

        elapsed = time.time() - start
        total = n_iterations * len(test_texts)

        print("Benchmark results:")
        print(f"  Texts processed: {total}")
        print(f"  Time: {elapsed:.2f}s")
        print(f"  Throughput: {total/elapsed:.0f} texts/sec")
        print(f"  Avg latency: {elapsed/total*1000:.2f}ms")


def cmd_process(args):
    """Process a file (image, PDF, etc.) and extract/redact PHI."""
    config = get_config(args)
    api_key = get_api_key()

    file_path = Path(args.file).expanduser()
    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing: {file_path}")
    print(f"Size: {file_path.stat().st_size:,} bytes")

    with get_scrubiq_with_key(config, api_key) as cr:
        content = file_path.read_bytes()

        from .files import FileProcessor
        processor = FileProcessor(cr)
        job = processor.process_file(content, file_path.name)

        if job.error:
            print(f"Error: {job.error}", file=sys.stderr)
            sys.exit(1)

        print(f"\n=== Processing Result ===")
        print(f"Status: {job.status.value}")
        print(f"Pages: {job.pages_total}")
        print(f"Processing time: {job.processing_time_ms:.0f}ms")
        print(f"PHI spans detected: {len(job.spans)}")

        if args.verbose and job.spans:
            print(f"\n=== Detected PHI ===")
            for span in job.spans[:20]:
                print(f"  {span.entity_type}: [{span.start}:{span.end}] (conf={span.confidence:.2f})")
            if len(job.spans) > 20:
                print(f"  ... and {len(job.spans) - 20} more")

        print(f"\n=== Extracted Text ===")
        if job.extracted_text:
            text_preview = job.extracted_text[:500]
            if len(job.extracted_text) > 500:
                text_preview += f"\n... ({len(job.extracted_text) - 500} more chars)"
            print(text_preview)
        else:
            print("(no text extracted)")

        if job.has_redacted_image and args.output:
            from .storage import ImageStore, ImageFileType
            if processor.image_store:
                result = processor.image_store.retrieve(job.id, ImageFileType.REDACTED)
                if result:
                    img_bytes, info = result
                    output_path = Path(args.output).expanduser()
                    output_path.write_bytes(img_bytes)
                    print(f"\nRedacted image saved to: {output_path}")
                else:
                    result = processor.image_store.retrieve(job.id, ImageFileType.REDACTED_PDF)
                    if result:
                        pdf_bytes, info = result
                        output_path = Path(args.output).expanduser()
                        output_path.write_bytes(pdf_bytes)
                        print(f"\nRedacted PDF saved to: {output_path}")
        elif job.has_redacted_image and not args.output:
            print(f"\nRedacted image available. Use -o/--output to save it.")


def cmd_demo(args):
    """Run interactive demo."""
    config = get_config(args)
    api_key = get_api_key()

    test_cases = [
        "Patient John Smith, SSN 123-45-6789",
        "Call Dr. Jane Doe at (555) 123-4567",
        "DOB: 03/15/1945, patient is 92 years old",
        "Email: patient@example.com, MRN: 12345678",
        "Credit card: 4111-1111-1111-1111",
        "Patient John Smith came in. He reported chest pain. His wife Sarah called.",
    ]

    print("=" * 60)
    print("SCRUBIQ DEMO")
    print("=" * 60)

    with get_scrubiq_with_key(config, api_key) as cr:
        for i, text in enumerate(test_cases, 1):
            print(f"\n[{i}] Original: {text}")

            result = cr.redact(text)
            print(f"    Redacted: {result.redacted}")
            print(f"    Spans: {len(result.spans)}")

            for span in result.spans:
                sh = f" -> {span.safe_harbor_value}" if span.safe_harbor_value and span.safe_harbor_value != span.text else ""
                print(f"      {span.entity_type}: '{span.text}'{sh}")

        print("\n" + "=" * 60)
        print("TOKEN STORE")
        print("=" * 60)

        for t in cr.get_tokens():
            print(f"  {t['token']}: {t['original']}")

        print("\n" + "=" * 60)
        print("AUDIT")
        print("=" * 60)

        valid, error = cr.verify_audit_chain()
        entries = cr.get_audit_entries(limit=5)

        print(f"Chain valid: {valid}")
        print(f"Recent entries: {len(entries)}")


def main():
    parser = argparse.ArgumentParser(
        prog='scrubiq',
        description='PHI/PII Detection & Redaction Pipeline',
        epilog='Set SCRUBIQ_API_KEY environment variable for authentication.'
    )
    parser.add_argument('--data-dir', help='Data directory path')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # keys - key management
    p_keys = subparsers.add_parser('keys', help='API key management')
    keys_sub = p_keys.add_subparsers(dest='keys_command', help='Key commands')

    # keys create
    p_keys_create = keys_sub.add_parser('create', help='Create a new API key')
    p_keys_create.add_argument('--name', '-n', required=True, help='Key name (e.g., "production")')
    p_keys_create.add_argument('--rate-limit', '-r', type=int, default=1000, help='Max requests per minute')
    p_keys_create.add_argument('--permissions', '-p', help='Comma-separated permissions (redact,restore,chat,admin,files)')
    p_keys_create.add_argument('--force', '-f', action='store_true', help='Force create without auth (first key only)')

    # keys list
    p_keys_list = keys_sub.add_parser('list', help='List all API keys')
    p_keys_list.add_argument('--all', '-a', action='store_true', help='Include revoked keys')

    # keys revoke
    p_keys_revoke = keys_sub.add_parser('revoke', help='Revoke an API key')
    p_keys_revoke.add_argument('prefix', help='Key prefix to revoke (e.g., sk-7Kx9)')

    # redact
    p_redact = subparsers.add_parser('redact', help='Redact text')
    p_redact.add_argument('text', nargs='?', help='Text to redact (or use stdin)')
    p_redact.add_argument('-v', '--verbose', action='store_true')

    # restore
    p_restore = subparsers.add_parser('restore', help='Restore tokens')
    p_restore.add_argument('text', nargs='?', help='Text with tokens (or use stdin)')
    p_restore.add_argument('--safe-harbor', action='store_true', help='Use Safe Harbor values')

    # tokens
    subparsers.add_parser('tokens', help='List tokens')

    # audit
    p_audit = subparsers.add_parser('audit', help='Show audit log')
    p_audit.add_argument('--verify', action='store_true', help='Verify chain integrity')
    p_audit.add_argument('--limit', type=int, default=20, help='Max entries')
    p_audit.add_argument('-v', '--verbose', action='store_true')

    # bench
    p_bench = subparsers.add_parser('bench', help='Run benchmark')
    p_bench.add_argument('-n', '--iterations', type=int, default=100)

    # demo
    subparsers.add_parser('demo', help='Run demo')

    # process (file)
    p_process = subparsers.add_parser('process', help='Process a file (image, PDF, etc.)')
    p_process.add_argument('file', help='Path to file to process')
    p_process.add_argument('-o', '--output', help='Output path for redacted image/PDF')
    p_process.add_argument('-v', '--verbose', action='store_true', help='Show detected PHI spans')

    args = parser.parse_args()

    # Handle keys subcommands
    if args.command == 'keys':
        if args.keys_command == 'create':
            cmd_keys_create(args)
        elif args.keys_command == 'list':
            cmd_keys_list(args)
        elif args.keys_command == 'revoke':
            cmd_keys_revoke(args)
        else:
            p_keys.print_help()
    elif args.command == 'redact':
        cmd_redact(args)
    elif args.command == 'restore':
        cmd_restore(args)
    elif args.command == 'tokens':
        cmd_tokens(args)
    elif args.command == 'audit':
        cmd_audit(args)
    elif args.command == 'bench':
        cmd_bench(args)
    elif args.command == 'demo':
        cmd_demo(args)
    elif args.command == 'process':
        cmd_process(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
