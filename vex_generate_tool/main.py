"""
Main CLI entry point for the VEX Edit Tool.
"""

import argparse
import sys
import json
from typing import Optional

from .generator import VEXEditor, VEXStatus, VEXJustification, VEXFormat


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog='vex-edit-tool',
        description='Edit VEX documents in CycloneDX, CSAF, and OpenVEX JSON formats',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate new VEX for not_affected status from cve-bin-tool output
  vex-edit-tool --cve-bin-json input.json --vuln-id CVE-2021-44228 \\
    --status not_affected --justification vulnerable_code_not_present \\
    --output vex_output.json

  # Edit existing VEX file
  vex-edit-tool --input-vex existing.json --vuln-id CVE-2021-44228 \\
    --status fixed --impact-statement "Patched in version 2.15.0"

  # Generate new VEX for affected status
  vex-edit-tool --cve-bin-json input.json --vuln-id CVE-2021-44228 \\
    --status affected --impact-statement "This vulnerability affects our product."
        """
    )
    
    # Input source arguments (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--cve-bin-json',
        help='Path to the JSON output file from cve-bin-tool (for generating new VEX)'
    )
    input_group.add_argument(
        '--input-vex',
        help='Path to existing VEX document to edit'
    )
    
    parser.add_argument(
        '--vuln-id',
        required=True,
        help='The CVE identifier (e.g., CVE-2021-44228)'
    )
    
    parser.add_argument(
        '--status',
        required=True,
        choices=[
            VEXStatus.NOT_AFFECTED,
            VEXStatus.AFFECTED,
            VEXStatus.FIXED,
            VEXStatus.UNDER_INVESTIGATION
        ],
        help='VEX status for the vulnerability'
    )
    
    parser.add_argument(
        '--justification',
        choices=[
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST
        ],
        help='Justification for the status (required for not_affected status)'
    )
    
    parser.add_argument(
        '--impact-statement',
        help='Detailed description of the impact'
    )
    
    parser.add_argument(
        '--output',
        help='Path to save the VEX file (prints to stdout if not provided, overwrites input if editing existing VEX)'
    )
    
    parser.add_argument(
        '--format',
        choices=['cyclonedx', 'csaf', 'openvex'],
        default='cyclonedx',
        help='Output format for new VEX documents (default: cyclonedx)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments."""
    # Check if justification is required for not_affected status
    if args.status == VEXStatus.NOT_AFFECTED and not args.justification:
        raise ValueError("--justification is required when status is 'not_affected'")
    
    # Validate that either cve-bin-json or input-vex is provided
    if not args.cve_bin_json and not args.input_vex:
        raise ValueError("Either --cve-bin-json or --input-vex must be provided")


def main() -> None:
    """Main entry point for the CLI application."""
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        # Validate arguments
        validate_arguments(args)
        
        # Create VEX editor
        editor = VEXEditor()
        
        # Determine operation mode
        if args.input_vex:
            # Edit existing VEX file
            vex_json = editor.edit_existing_vex_file(
                input_file=args.input_vex,
                vuln_id=args.vuln_id,
                status=args.status,
                justification=args.justification,
                impact_statement=args.impact_statement,
                output_file=args.output
            )
        else:
            # Generate new VEX document from cve-bin-tool output
            vex_json = editor.generate_vex_from_file(
                input_file=args.cve_bin_json,
                vuln_id=args.vuln_id,
                status=args.status,
                justification=args.justification,
                impact_statement=args.impact_statement
            )
        
        # Output the result
        if args.input_vex and args.output:
            # For VEX editing with explicit output, file already saved
            print(f"VEX document edited successfully: {args.output}")
        elif args.input_vex and not args.output:
            # For VEX editing without explicit output, file was overwritten
            print(f"VEX document edited successfully: {args.input_vex}")
        elif args.output:
            # For new VEX generation with output file
            with open(args.output, 'w', encoding='utf-8') as f:
                # Parse and re-format for pretty printing
                parsed_json = json.loads(vex_json)
                json.dump(parsed_json, f, indent=2, ensure_ascii=False)
            print(f"VEX document generated successfully: {args.output}")
        else:
            # Print to stdout
            # Parse and re-format for pretty printing
            parsed_json = json.loads(vex_json)
            print(json.dumps(parsed_json, indent=2, ensure_ascii=False))
    
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
