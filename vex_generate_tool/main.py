"""
Main CLI entry point for the VEX Generate Tool.
"""

import argparse
import sys
import json
from typing import Optional

from .generator import VEXGenerator, VEXStatus, VEXJustification


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog='vex-generate-tool',
        description='Generate VEX documents in CycloneDX JSON format from cve-bin-tool output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate VEX for not_affected status
  vex-generate-tool --cve-bin-json input.json --vuln-id CVE-2021-44228 \\
    --status not_affected --justification vulnerable_code_not_present \\
    --output vex_output.json

  # Generate VEX for affected status
  vex-generate-tool --cve-bin-json input.json --vuln-id CVE-2021-44228 \\
    --status affected --impact-statement "This vulnerability affects our product."

  # Output to stdout
  vex-generate-tool --cve-bin-json input.json --vuln-id CVE-2021-44228 \\
    --status fixed
        """
    )
    
    parser.add_argument(
        '--cve-bin-json',
        required=True,
        help='Path to the JSON output file from cve-bin-tool'
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
        help='Path to save the generated VEX file (prints to stdout if not provided)'
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


def main() -> None:
    """Main entry point for the CLI application."""
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        # Validate arguments
        validate_arguments(args)
        
        # Create VEX generator
        generator = VEXGenerator()
        
        # Generate VEX document
        vex_json = generator.generate_vex_from_file(
            input_file=args.cve_bin_json,
            vuln_id=args.vuln_id,
            status=args.status,
            justification=args.justification,
            impact_statement=args.impact_statement
        )
        
        # Output the result
        if args.output:
            # Write to file
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
