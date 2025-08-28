"""
Enhanced error handling for the VEX Updater Tool.

Provides actionable error messages and robust validation for the multi-file workflow.
"""

import json
import sys
from typing import Optional, Dict, Any, List
from pathlib import Path


class VEXError(Exception):
    """Base exception for VEX-related errors."""
    
    def __init__(self, message: str, suggestion: Optional[str] = None):
        self.message = message
        self.suggestion = suggestion
        super().__init__(self.message)
    
    def print_error(self) -> None:
        """Print the error with suggestion if available."""
        print(f"❌ {self.message}", file=sys.stderr)
        if self.suggestion:
            print(f"💡 {self.suggestion}", file=sys.stderr)


class ScanReportError(VEXError):
    """Error related to scan report processing."""
    
    def __init__(self, message: str, file_path: str, line_number: Optional[int] = None, 
                 expected_format: Optional[str] = None, found_structure: Optional[str] = None):
        self.file_path = file_path
        self.line_number = line_number
        self.expected_format = expected_format
        self.found_structure = found_structure
        
        # Build detailed message
        details = []
        if line_number:
            details.append(f"at line {line_number}")
        if found_structure:
            details.append(f"found: {found_structure}")
        if expected_format:
            details.append(f"expected: {expected_format}")
        
        detail_str = f" ({', '.join(details)})" if details else ""
        full_message = f"{message}{detail_str}"
        
        # Build suggestion
        suggestion = self._build_suggestion()
        
        super().__init__(full_message, suggestion)
    
    def _build_suggestion(self) -> Optional[str]:
        """Build helpful suggestion based on error type."""
        if "format" in self.message.lower():
            return ("Re-run cve-bin-tool with --format json flag. "
                   f"Example: cve-bin-tool . --format json -o {Path(self.file_path).name}")
        elif "not found" in self.message.lower():
            return f"Check that the file exists and is readable: {self.file_path}"
        elif "invalid json" in self.message.lower():
            return "Validate JSON syntax using a JSON validator or try regenerating the scan report"
        return None


class VEXFileError(VEXError):
    """Error related to VEX file processing."""
    
    def __init__(self, message: str, file_path: str, vuln_id: Optional[str] = None, 
                 field_name: Optional[str] = None, line_number: Optional[int] = None):
        self.file_path = file_path
        self.vuln_id = vuln_id
        self.field_name = field_name
        self.line_number = line_number
        
        # Build detailed message
        details = []
        if vuln_id:
            details.append(f"vulnerability '{vuln_id}'")
        if field_name:
            details.append(f"field '{field_name}'")
        if line_number:
            details.append(f"line {line_number}")
        
        detail_str = f" ({', '.join(details)})" if details else ""
        full_message = f"{message}{detail_str}"
        
        # Build suggestion
        suggestion = self._build_suggestion()
        
        super().__init__(full_message, suggestion)
    
    def _build_suggestion(self) -> Optional[str]:
        """Build helpful suggestion based on error type."""
        if self.field_name == "status":
            return ("Add a valid status: 'not_affected', 'affected', 'fixed', or 'under_investigation'. "
                   "Example: {\"status\": \"not_affected\", \"justification\": \"vulnerable_code_not_present\"}")
        elif self.field_name == "justification":
            return ("Add justification for not_affected status: 'vulnerable_code_not_present', "
                   "'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary', "
                   "or 'inline_mitigations_already_exist'")
        elif "format" in self.message.lower():
            return "Ensure VEX file follows CycloneDX, CSAF, or OpenVEX specification"
        return None


class ValidationError(VEXError):
    """Error related to data validation."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[str] = None,
                 expected_values: Optional[List[str]] = None):
        self.field = field
        self.value = value
        self.expected_values = expected_values
        
        # Build detailed message
        details = []
        if field:
            details.append(f"field '{field}'")
        if value:
            details.append(f"value '{value}'")
        
        detail_str = f" ({', '.join(details)})" if details else ""
        full_message = f"{message}{detail_str}"
        
        # Build suggestion
        suggestion = self._build_suggestion()
        
        super().__init__(full_message, suggestion)
    
    def _build_suggestion(self) -> Optional[str]:
        """Build helpful suggestion based on error type."""
        if self.expected_values:
            return f"Use one of: {', '.join(self.expected_values)}"
        elif self.field == "vuln_id":
            return "CVE ID must follow format: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"
        return None


class WorkflowError(VEXError):
    """Error related to workflow operations."""
    
    def __init__(self, message: str, operation: Optional[str] = None, recovery_steps: Optional[List[str]] = None):
        self.operation = operation
        self.recovery_steps = recovery_steps or []
        
        # Build detailed message
        if operation:
            full_message = f"{message} (operation: {operation})"
        else:
            full_message = message
        
        # Build suggestion
        suggestion = self._build_suggestion()
        
        super().__init__(full_message, suggestion)
    
    def _build_suggestion(self) -> Optional[str]:
        """Build helpful suggestion based on error type."""
        if self.recovery_steps:
            return "Recovery steps:\n" + "\n".join(f"  • {step}" for step in self.recovery_steps)
        return None


def handle_file_not_found(file_path: str, file_type: str = "file") -> None:
    """Handle file not found errors with helpful suggestions."""
    error = ScanReportError(
        f"{file_type.capitalize()} not found",
        file_path,
        found_structure="file does not exist"
    )
    error.print_error()
    sys.exit(1)


def handle_json_parsing_error(file_path: str, error: json.JSONDecodeError) -> None:
    """Handle JSON parsing errors with line numbers and suggestions."""
    error_obj = ScanReportError(
        f"Invalid JSON in {Path(file_path).name}",
        file_path,
        line_number=error.lineno,
        found_structure=f"JSON syntax error: {error.msg}"
    )
    error_obj.print_error()
    sys.exit(1)


def handle_scan_report_validation(scan_data: Dict[str, Any], file_path: str) -> None:
    """Validate scan report format and provide specific guidance."""
    if not isinstance(scan_data, dict):
        raise ScanReportError(
            "Scan report must be a JSON object",
            file_path,
            expected_format="JSON object with 'components' array",
            found_structure=f"found {type(scan_data).__name__}"
        )
    
    if "components" not in scan_data:
        raise ScanReportError(
            "Missing 'components' field in scan report",
            file_path,
            expected_format="JSON object with 'components' array",
            found_structure=f"found keys: {list(scan_data.keys())}"
        )
    
    if not isinstance(scan_data["components"], list):
        raise ScanReportError(
            "'components' field must be an array",
            file_path,
            expected_format="array of component objects",
            found_structure=f"found {type(scan_data['components']).__name__}"
        )


def handle_vex_validation(vex_data: Dict[str, Any], file_path: str) -> None:
    """Validate VEX file format and provide specific guidance."""
    if not isinstance(vex_data, dict):
        raise VEXFileError(
            "VEX file must be a JSON object",
            file_path,
            found_structure=f"found {type(vex_data).__name__}"
        )
    
    # Check for required VEX fields based on format
    if "bomFormat" in vex_data and vex_data["bomFormat"] == "CycloneDX":
        if "vulnerabilities" not in vex_data:
            raise VEXFileError(
                "Missing 'vulnerabilities' array in CycloneDX VEX",
                file_path,
                expected_format="CycloneDX VEX with 'vulnerabilities' array"
            )
    
    # Additional format-specific validation can be added here


def handle_cve_validation(cve_id: str) -> None:
    """Validate CVE ID format and provide correction examples."""
    if not cve_id.startswith("CVE-"):
        raise ValidationError(
            "Invalid CVE ID format",
            field="vuln_id",
            value=cve_id,
            expected_values=["CVE-YYYY-NNNNN format"]
        )
    
    # Basic CVE format validation
    parts = cve_id.split("-")
    if len(parts) != 3:
        raise ValidationError(
            "CVE ID must have exactly 3 parts separated by hyphens",
            field="vuln_id",
            value=cve_id,
            expected_values=["CVE-YYYY-NNNNN format"]
        )
    
    try:
        year = int(parts[1])
        if year < 1999 or year > 2030:
            raise ValidationError(
                "CVE year must be between 1999 and 2030",
                field="vuln_id",
                value=cve_id
            )
    except ValueError:
        raise ValidationError(
            "CVE year must be a valid number",
            field="vuln_id",
            value=cve_id
        )


def handle_interrupted_session() -> None:
    """Handle interrupted triage sessions with clear resume instructions."""
    error = WorkflowError(
        "Triage session was interrupted",
        operation="interactive_triage",
        recovery_steps=[
            "Re-run the same command to resume",
            "Use --auto-skip-existing to skip already processed vulnerabilities",
            "Check the backup file if --backup was used"
        ]
    )
    error.print_error()
    sys.exit(130)


def handle_large_file_warning(file_path: str, size_mb: float, threshold_mb: float = 50) -> None:
    """Warn about large files and provide optimization suggestions."""
    if size_mb > threshold_mb:
        print(f"⚠️  Large file detected: {Path(file_path).name} ({size_mb:.1f}MB)", file=sys.stderr)
        print(f"💡 Consider using --dry-run first to preview changes", file=sys.stderr)
        print(f"💡 Use --diff-only to see changes without processing", file=sys.stderr)
