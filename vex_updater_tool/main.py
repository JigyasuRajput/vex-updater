"""
Main CLI entry point for the VEX Updater Tool.

This refactored main module supports the new updater workflow with enhanced safety
and backward compatibility for single vulnerability operations.
"""

import argparse
import sys
import json
import os
import logging
from typing import Optional

from .updater import VEXUpdater
from .vex_parser import VEXStatus, VEXJustification, VEXFormat
from .user_guidance import UserGuidance
from .generator import VEXEditor


def setup_logging(debug_level: str) -> None:
    """Setup logging configuration based on debug level."""
    # Map debug levels to logging levels
    level_map = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    
    log_level = level_map.get(debug_level.lower(), logging.INFO)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Set specific logger levels for the application
    loggers = [
        'vex_updater_tool',
        'vex_updater_tool.main',
        'vex_updater_tool.updater',
        'vex_updater_tool.scan_parser',
        'vex_updater_tool.vex_parser',
        'vex_updater_tool.diff_engine',
        'vex_updater_tool.interactive_triage',
        'vex_updater_tool.user_guidance',
        'vex_updater_tool.generator'
    ]
    
    for logger_name in loggers:
        logging.getLogger(logger_name).setLevel(log_level)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog='vex-updater',
        description='Update VEX documents by comparing scan reports with existing VEX files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog="""
Examples:
  # Safe default - outputs to new file
  vex-updater --scan-report latest_scan.json --vex-file project_vex.json

  # Explicit in-place update with backup
  vex-updater --scan-report latest_scan.json --vex-file project_vex.json --in-place --backup

  # Show diff only
  vex-updater --scan-report latest_scan.json --vex-file project_vex.json --diff-only

  # Dry run to see what would be updated
  vex-updater --scan-report latest_scan.json --vex-file project_vex.json --dry-run

  # Debug mode with detailed logging
  vex-updater --scan-report latest_scan.json --vex-file project_vex.json --debug debug

  # Single vulnerability mode: Update specific vulnerability
  vex-updater --cve-bin-json scan.json --input-vex existing.json --vuln-id CVE-2021-44228 \\
    --status fixed --impact-statement "Patched in version 2.15.0"
        """
    )
    
    # Debug option
    parser.add_argument(
        '--debug',
        choices=['debug', 'info', 'warning', 'error', 'critical'],
        default='warning',
        help='Set debug level for detailed logging output (default: warning)'
    )
    
    # Primary updater arguments (new workflow)
    parser.add_argument(
        '--scan-report',
        help='Path to cve-bin-tool JSON output (required for updater workflow)'
    )
    
    parser.add_argument(
        '--vex-file',
        help='Path to existing VEX file to update (required for updater workflow)'
    )
    
    parser.add_argument(
        '--output-file',
        help='Path for updated VEX file (optional, defaults to stdout or project_vex.updated.json)'
    )
    
    # Backward compatibility aliases
    parser.add_argument(
        '--scan-file',
        help=' Alias for --scan-report'
    )
    
    parser.add_argument(
        '--output',
        help=' Alias for --output-file'
    )
    
    # Safety enhancements
    parser.add_argument(
        '--in-place', '-i',
        action='store_true',
        help='Overwrite the original VEX file (requires explicit flag for safety)'
    )
    
    parser.add_argument(
        '--backup',
        action='store_true',
        help='Create backup of original VEX file before modification'
    )
    
    # Operational modes
    parser.add_argument(
        '--interactive',
        action='store_true',
        default=True,
        help='Use interactive triage session (default)'
    )
    
    parser.add_argument(
        '--no-interactive',
        action='store_true',
        help='Disable interactive triage session (run in batch mode)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be updated without making changes'
    )
    
    parser.add_argument(
        '--diff-only',
        action='store_true',
        help='Just show the diff without prompting for updates'
    )
    
    parser.add_argument(
        '--auto-skip-existing',
        action='store_true',
        help='Don\'t prompt for vulnerabilities already in VEX'
    )
    
    # Single vulnerability mode arguments
    parser.add_argument(
        '--cve-bin-json',
        help=' Path to the JSON output file from cve-bin-tool'
    )
    
    parser.add_argument(
        '--input-vex',
        help=' Path to existing VEX document to edit'
    )
    
    parser.add_argument(
        '--vuln-id',
        help=' The CVE identifier (e.g., CVE-2021-44228)'
    )
    
    parser.add_argument(
        '--status',
        choices=[
            VEXStatus.NOT_AFFECTED,
            VEXStatus.AFFECTED,
            VEXStatus.FIXED,
            VEXStatus.UNDER_INVESTIGATION
        ],
        help=' VEX status for the vulnerability'
    )
    
    parser.add_argument(
        '--justification',
        choices=[
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST
        ],
        help=' Justification for the status (required for not_affected status)'
    )
    
    parser.add_argument(
        '--impact-statement',
        help=' Detailed description of the impact'
    )
    
    # Format options
    parser.add_argument(
        '--format',
        choices=['cyclonedx', 'csaf', 'openvex'],
        default='cyclonedx',
        help='Output format for new VEX documents (default: cyclonedx)'
    )
    
    # Utility options
    parser.add_argument(
        '--explain',
        choices=['status', 'justification', 'format', 'workflow', 'best-practices'],
        help='Show detailed explanations for VEX concepts'
    )
    
    parser.add_argument(
        '--validate-only',
        action='store_true',
        help='Validate inputs without making changes'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments."""
    # Skip validation for special modes
    if getattr(args, 'explain', None):
        return
    
    # Map deprecated arguments to new ones
    if hasattr(args, 'scan_file') and args.scan_file and not getattr(args, 'scan_report', None):
        args.scan_report = args.scan_file
        print("⚠️  Warning: --scan-file is deprecated, use --scan-report instead", file=sys.stderr)
    
    if hasattr(args, 'output') and args.output and not getattr(args, 'output_file', None):
        args.output_file = args.output
        print("⚠️  Warning: --output is deprecated, use --output-file instead", file=sys.stderr)
    
    # Determine operation mode
    is_single_vuln_mode = bool(
        getattr(args, 'cve_bin_json', None) or 
        getattr(args, 'input_vex', None) or 
        getattr(args, 'vuln_id', None) or 
        getattr(args, 'status', None)
    )
    is_updater_mode = bool(getattr(args, 'scan_report', None) or getattr(args, 'vex_file', None))
    
    # Validate operation mode
    if is_single_vuln_mode and is_updater_mode:
        raise ValueError(
            "Cannot mix single vulnerability and updater workflow arguments. "
            "Use either single vulnerability arguments (--cve-bin-json, --input-vex, --vuln-id, --status) "
            "or updater arguments (--scan-report, --vex-file). "
            "See --help for usage examples."
        )
    
    if not is_single_vuln_mode and not is_updater_mode:
        raise ValueError(
            "Must specify either single vulnerability arguments or updater workflow arguments. "
            "For single vulnerability mode: use --cve-bin-json or --input-vex with --vuln-id and --status. "
            "For updater mode: use --scan-report and --vex-file. "
            "Run --help for detailed usage information."
        )
    
    # Handle single vulnerability mode validation
    if is_single_vuln_mode:
        validate_single_vuln_arguments(args)
        return
    
    # Validate updater workflow
    validate_updater_arguments(args)


def validate_single_vuln_arguments(args: argparse.Namespace) -> None:
    """Validate single vulnerability mode arguments."""
    # Check required arguments for single vulnerability operation
    if not args.vuln_id:
        raise ValueError(
            "--vuln-id is required in single vulnerability mode. "
            "Use format: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"
        )
    
    if not args.status:
        raise ValueError(
            "--status is required in single vulnerability mode. "
            "Valid values: not_affected, affected, fixed, under_investigation"
        )
    
    # Validate CVE ID format
    if not args.vuln_id.startswith("CVE-"):
        raise ValueError(
            f"Invalid CVE ID format: {args.vuln_id}. "
            "Must start with 'CVE-' followed by year and number (e.g., CVE-2021-44228)"
        )
    
    # Check if justification is required for not_affected status
    if args.status == VEXStatus.NOT_AFFECTED and not args.justification:
        raise ValueError(
            "--justification is required when status is 'not_affected'. "
            "Valid values: vulnerable_code_not_present, vulnerable_code_not_in_execute_path, "
            "vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist"
        )
    
    # Validate that either cve-bin-json or input-vex is provided
    if not args.cve_bin_json and not args.input_vex:
        raise ValueError(
            "Either --cve-bin-json or --input-vex must be provided in single vulnerability mode. "
            "Use --cve-bin-json <file> to generate VEX from scan report, "
            "or --input-vex <file> to edit existing VEX file. "
            "Both require --vuln-id and --status arguments."
        )


def validate_updater_arguments(args: argparse.Namespace) -> None:
    """Validate updater workflow arguments."""
    # Check required arguments
    if not args.scan_report:
        raise ValueError(
            "--scan-report is required for updater workflow. "
            "Provide path to cve-bin-tool JSON output file."
        )
    
    if not args.vex_file:
        raise ValueError(
            "--vex-file is required for updater workflow. "
            "Provide path to existing VEX file to update."
        )
    
    # Validate file existence
    if not os.path.exists(args.scan_report):
        raise FileNotFoundError(f"Scan report file not found: {args.scan_report}")
    
    if not os.path.exists(args.vex_file):
        raise FileNotFoundError(f"VEX file not found: {args.vex_file}")
    
    # Check file sizes and warn about large files
    try:
        scan_size = os.path.getsize(args.scan_report) / (1024 * 1024)  # MB
        vex_size = os.path.getsize(args.vex_file) / (1024 * 1024)  # MB
        
        if scan_size > 50:
            print(f"⚠️  Large scan report detected: {os.path.basename(args.scan_report)} ({scan_size:.1f}MB)", file=sys.stderr)
            print(f"💡 Consider using --dry-run first to preview changes", file=sys.stderr)
        
        if vex_size > 50:
            print(f"⚠️  Large VEX file detected: {os.path.basename(args.vex_file)} ({vex_size:.1f}MB)", file=sys.stderr)
            print(f"💡 Consider using --diff-only to see changes without processing", file=sys.stderr)
    except OSError:
        pass  # Skip size check if we can't get file size
    
    # Validate operational modes
    # When dry-run or diff-only is specified, interactive should be disabled
    if getattr(args, 'dry_run', False) or getattr(args, 'diff_only', False):
        args.interactive = False
    
    # Handle --no-interactive flag
    if getattr(args, 'no_interactive', False):
        args.interactive = False
    
    explicit_modes = [
        getattr(args, 'dry_run', False),
        getattr(args, 'diff_only', False)
    ]
    
    if sum(explicit_modes) > 1:
        raise ValueError(
            "Cannot use multiple operational modes. "
            "Choose one: --dry-run or --diff-only. "
            "--dry-run: shows what would be changed without making changes, "
            "--diff-only: shows differences without prompting."
        )
    
    # Validate safety options
    if getattr(args, 'in_place', False) and not args.vex_file:
        raise ValueError(
            "--in-place requires --vex-file. "
            "Use with --vex-file to overwrite original file."
        )
    
    if getattr(args, 'backup', False) and not getattr(args, 'in_place', False):
        print("⚠️  Warning: --backup is most useful with --in-place", file=sys.stderr)


def determine_output_file(args: argparse.Namespace) -> str:
    """Determine the output file path based on arguments."""
    if getattr(args, 'output_file', None):
        return args.output_file
    
    if getattr(args, 'in_place', False):
        return args.vex_file
    
    # Default: create new file with .updated.json suffix
    base_name = os.path.splitext(args.vex_file)[0]
    return f"{base_name}.updated.json"


def create_backup(vex_file: str) -> str:
    """Create a backup of the VEX file."""
    backup_file = f"{vex_file}.backup"
    
    try:
        with open(vex_file, 'r', encoding='utf-8') as src:
            with open(backup_file, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        print(f"✅ Backup created: {backup_file}")
        return backup_file
    except Exception as e:
        print(f"⚠️  Warning: Could not create backup: {e}", file=sys.stderr)
        return ""


def show_explanation(topic: str, args: argparse.Namespace) -> None:
    """Show detailed explanations for VEX concepts."""
    guidance = UserGuidance()
    
    if topic == 'status':
        print(guidance.format_guidance_output(
            f"VEX STATUS VALUES EXPLAINED\n\n" +
            f"• not_affected:\n  {guidance.get_status_explanation(VEXStatus.NOT_AFFECTED)}\n\n" +
            f"• affected:\n  {guidance.get_status_explanation(VEXStatus.AFFECTED)}\n\n" +
            f"• fixed:\n  {guidance.get_status_explanation(VEXStatus.FIXED)}\n\n" +
            f"• under_investigation:\n  {guidance.get_status_explanation(VEXStatus.UNDER_INVESTIGATION)}"
        ))
    
    elif topic == 'justification':
        print(guidance.format_guidance_output(
            f"VEX JUSTIFICATION VALUES EXPLAINED\n\n" +
            f"(Required only for 'not_affected' status)\n\n" +
            f"• vulnerable_code_not_present:\n  {guidance.get_justification_explanation(VEXJustification.VULNERABLE_CODE_NOT_PRESENT)}\n\n" +
            f"• vulnerable_code_not_in_execute_path:\n  {guidance.get_justification_explanation(VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH)}\n\n" +
            f"• vulnerable_code_cannot_be_controlled_by_adversary:\n  {guidance.get_justification_explanation(VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY)}\n\n" +
            f"• inline_mitigations_already_exist:\n  {guidance.get_justification_explanation(VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST)}"
        ))
    
    elif topic == 'format':
        print(guidance.format_guidance_output(
            f"VEX DOCUMENT FORMATS EXPLAINED\n\n" +
            f"• CycloneDX:\n  {guidance.get_format_explanation('cyclonedx')}\n\n" +
            f"• CSAF:\n  {guidance.get_format_explanation('csaf')}\n\n" +
            f"• OpenVEX:\n  {guidance.get_format_explanation('openvex')}"
        ))
    
    elif topic == 'workflow':
        print(guidance.format_guidance_output(
            guidance.get_workflow_guidance('updating_existing'),
            "UPDATING EXISTING VEX DOCUMENTS"
        ))
        print(guidance.format_guidance_output(
            guidance.get_workflow_guidance('first_time'),
            "CREATING NEW VEX DOCUMENTS"
        ))
    
    elif topic == 'best-practices':
        practices = guidance.get_best_practices()
        mistakes = guidance.get_common_mistakes()
        
        content = "VEX BEST PRACTICES:\n\n"
        for i, practice in enumerate(practices, 1):
            content += f"{i}. {practice}\n"
        
        content += "\n\nCOMMON MISTAKES TO AVOID:\n\n"
        for mistake in mistakes:
            content += f"❌ {mistake['mistake']}\n"
            content += f"✅ {mistake['fix']}\n"
            content += f"   Example: {mistake['example']}\n\n"
        
        print(guidance.format_guidance_output(content, "VEX BEST PRACTICES"))


def run_single_vuln_mode(args: argparse.Namespace) -> None:
    """Run the tool in single vulnerability mode."""
    print("🚀 Running in single vulnerability mode.")
    
    # Use the imported VEXEditor for single vulnerability operations
    editor = VEXEditor()
    
    if args.input_vex:
        # Edit existing VEX file
        vex_json = editor.edit_existing_vex_file(
            input_file=args.input_vex,
            vuln_id=args.vuln_id,
            status=args.status,
            justification=args.justification,
            impact_statement=args.impact_statement,
            output_file=args.output_file
        )
        
        if args.output_file:
            print(f"VEX document edited successfully: {args.output_file}")
        else:
            print(f"VEX document edited successfully: {args.input_vex}")
            
    else:
        # Generate new VEX document from scan
        vex_json = editor.generate_vex_from_file(
            input_file=args.cve_bin_json,
            vuln_id=args.vuln_id,
            status=args.status,
            justification=args.justification,
            impact_statement=args.impact_statement,
            vex_format=getattr(args, 'format', 'cyclonedx')
        )
        
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                parsed_json = json.loads(vex_json)
                json.dump(parsed_json, f, indent=2, ensure_ascii=False)
            print(f"VEX document generated successfully: {args.output_file}")
        else:
            parsed_json = json.loads(vex_json)
            print(json.dumps(parsed_json, indent=2, ensure_ascii=False))


def run_updater_workflow(args: argparse.Namespace) -> None:
    """Run the new updater workflow."""
    print("🚀 Running VEX Updater workflow...")
    
    # Create VEX updater
    updater = VEXUpdater()
    
    # Validate inputs
    if args.validate_only:
        print("🔍 Validating inputs...")
        errors = updater.validate_inputs(args.scan_report, args.vex_file)
        if errors:
            print("❌ Validation errors found:")
            for error in errors:
                print(f"  • {error}")
            sys.exit(1)
        else:
            print("✅ All inputs are valid.")
            return
    
    # Determine output file
    output_file = determine_output_file(args)
    
    # Create backup if requested
    backup_file = ""
    if args.backup and args.in_place:
        backup_file = create_backup(args.vex_file)
    
    # Determine operation mode
    if args.dry_run:
        print("🔍 Running in dry-run mode (no changes will be made)...")
        result = updater.dry_run_update(
            scan_file=args.scan_report,
            vex_file=args.vex_file
        )
    elif args.diff_only:
        print("🔍 Running in diff-only mode...")
        result = updater.show_diff_only(
            scan_file=args.scan_report,
            vex_file=args.vex_file
        )
    else:
        # Interactive or batch mode
        print("🔄 Updating VEX document...")
        result = updater.update_vex_from_scan_enhanced(
            scan_file=args.scan_report,
            vex_file=args.vex_file,
            output_file=output_file,
            interactive=getattr(args, 'interactive', True),
            auto_skip_existing=getattr(args, 'auto_skip_existing', False)
        )
    
    # Display results
    print(f"\n🎉 Operation completed successfully!")
    
    if 'status' in result:
        print(f"   Status: {result['status']}")
    
    if 'output_file' in result:
        print(f"   Output file: {result['output_file']}")
    
    if 'applied_changes' in result:
        print(f"   Applied changes: {result['applied_changes']}")
    
    if 'summary' in result:
        summary = result['summary']
        if summary.get('new', 0) > 0 or summary.get('removed', 0) > 0 or summary.get('updated', 0) > 0:
            print(f"   Summary: {summary.get('new', 0)} new, {summary.get('removed', 0)} removed, {summary.get('updated', 0)} updated")
    
    if backup_file:
        print(f"   Backup created: {backup_file}")


def main() -> None:
    """Main entry point for the CLI application."""
    logger = logging.getLogger(__name__)
    
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        # Setup logging first
        setup_logging(args.debug)
        logger.info("Starting VEX Updater Tool")
        logger.debug(f"Command line arguments: {args}")
        
        # Handle explanation requests first
        if args.explain:
            logger.info(f"Showing explanation for: {args.explain}")
            show_explanation(args.explain, args)
            return
        
        # Validate arguments
        logger.debug("Validating command line arguments")
        validate_arguments(args)
        
        # Determine operation mode and execute
        is_single_vuln_mode = bool(args.cve_bin_json or args.input_vex or args.vuln_id or args.status)
        
        if is_single_vuln_mode:
            logger.info("Running in single vulnerability mode")
            run_single_vuln_mode(args)
        else:
            logger.info("Running in updater workflow mode")
            run_updater_workflow(args)
    
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        print("\n\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()