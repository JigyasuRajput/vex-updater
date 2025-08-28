"""
User Guidance module - Provides helpful guidance and explanations for VEX concepts.
"""

from typing import Dict, List, Any
from .vex_parser import VEXStatus, VEXJustification


class UserGuidance:
    """Provides user guidance and explanations for VEX concepts."""
    
    def __init__(self):
        """Initialize the user guidance system."""
        pass
    
    def get_status_explanation(self, status: str) -> str:
        """Get explanation for a VEX status value."""
        explanations = {
            VEXStatus.NOT_AFFECTED: "The vulnerability is in a component but does not affect the product. A justification is required.",
            VEXStatus.AFFECTED: "The vulnerability affects the product. Consider providing an impact statement.",
            VEXStatus.FIXED: "The vulnerability has been fixed in the product. Consider providing version information.",
            VEXStatus.UNDER_INVESTIGATION: "The vulnerability impact is being investigated. Follow up when analysis is complete."
        }
        return explanations.get(status, f"Unknown status: {status}")
    
    def get_justification_explanation(self, justification: str) -> str:
        """Get explanation for a VEX justification value."""
        explanations = {
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT: "The vulnerable code is not included in the product.",
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: "The vulnerable code is present but cannot be executed.",
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: "The vulnerable code requires specific configuration that prevents exploitation.",
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST: "Built-in protections prevent the vulnerability from being exploited."
        }
        return explanations.get(justification, f"Unknown justification: {justification}")
    
    def get_format_explanation(self, vex_format: str) -> str:
        """Get explanation for a VEX document format."""
        explanations = {
            "cyclonedx": "Industry standard SBOM format with built-in VEX support. Good for CI/CD integration.",
            "csaf": "OASIS standard for security advisories. Comprehensive format for detailed vulnerability information.",
            "openvex": "Minimalist VEX format focused on simplicity and machine readability."
        }
        return explanations.get(vex_format, f"Unknown format: {vex_format}")
    
    def get_workflow_guidance(self, scenario: str) -> str:
        """Get workflow guidance for different scenarios."""
        workflows = {
            "first_time": """1. Start with your scan results (e.g., from cve-bin-tool)
2. Run vex-updater to create initial VEX document
3. Use interactive mode to triage each vulnerability
4. Choose appropriate status and justification
5. Save and share your VEX document with stakeholders""",
            
            "updating_existing": """1. Ensure you have both scan results and existing VEX
2. Run vex-updater in update mode
3. Review new vulnerabilities found in scan
4. Update status for vulnerabilities no longer in scan
5. Save updated VEX document""",
            
            "automation": """1. Set up default triage decisions for batch processing
2. Use non-interactive mode for CI/CD pipelines
3. Review and adjust automated decisions periodically
4. Implement approval workflows for critical vulnerabilities"""
        }
        return workflows.get(scenario, "Unknown scenario")
    
    def get_best_practices(self) -> List[str]:
        """Get list of VEX best practices."""
        return [
            "Always provide justification for 'not_affected' status",
            "Include detailed impact statements for affected vulnerabilities",
            "Update VEX documents promptly when new scans are available",
            "Use consistent vulnerability IDs across your toolchain",
            "Store VEX documents alongside your SBOMs",
            "Review and validate VEX decisions with security team",
            "Automate VEX updates in CI/CD pipelines where possible",
            "Maintain audit trail of VEX decision changes"
        ]
    
    def get_common_mistakes(self) -> List[Dict[str, str]]:
        """Get list of common mistakes and how to fix them."""
        return [
            {
                "mistake": "Using 'not_affected' without proper justification",
                "fix": "Always provide a specific justification from the allowed values",
                "example": "Use 'vulnerable_code_not_present' instead of generic explanations"
            },
            {
                "mistake": "Forgetting to update VEX when vulnerabilities are fixed",
                "fix": "Implement regular VEX update cycles aligned with your release process",
                "example": "Update status to 'fixed' when patches are deployed"
            },
            {
                "mistake": "Using vague impact statements",
                "fix": "Provide specific, actionable impact descriptions",
                "example": "Instead of 'might be affected', use 'RCE possible in admin interface'"
            },
            {
                "mistake": "Not coordinating VEX with SBOM updates",
                "fix": "Keep VEX and SBOM in sync as components change",
                "example": "Update both when dependencies are upgraded"
            }
        ]
    
    def validate_combination(self, status: str, justification: str = None) -> Dict[str, Any]:
        """Validate status and justification combination."""
        result = {
            'valid': True,
            'warnings': [],
            'suggestions': []
        }
        
        # Check if justification is required
        if status == VEXStatus.NOT_AFFECTED and not justification:
            result['valid'] = False
            result['warnings'].append("Justification is required for 'not_affected' status")
        
        # Check if justification is provided when not needed
        if status != VEXStatus.NOT_AFFECTED and justification:
            result['warnings'].append(f"Justification is typically not needed for '{status}' status")
        
        # Provide suggestions
        if status == VEXStatus.AFFECTED:
            result['suggestions'].append("Consider providing a detailed impact statement")
        
        if status == VEXStatus.FIXED:
            result['suggestions'].append("Consider including version or patch information")
        
        return result
    
    def generate_impact_statement_template(self, status: str, vuln_id: str) -> str:
        """Generate impact statement template based on status."""
        templates = {
            VEXStatus.NOT_AFFECTED: f"The {vuln_id} vulnerability does not affect this product because [explain why based on justification].",
            VEXStatus.AFFECTED: f"The {vuln_id} vulnerability affects this product. Impact: [describe specific impact]. Mitigation: [describe workarounds if any].",
            VEXStatus.FIXED: f"The {vuln_id} vulnerability has been fixed in version [version]. Users should upgrade to resolve this issue.",
            VEXStatus.UNDER_INVESTIGATION: f"The impact of {vuln_id} on this product is being investigated. Expected completion: [date]. Check for updates."
        }
        return templates.get(status, f"Impact statement for {vuln_id} with status {status}.")
    
    def format_guidance_output(self, content: str, title: str = None) -> str:
        """Format guidance content for display."""
        if title:
            formatted = f"\n{'='*len(title)}\n{title}\n{'='*len(title)}\n\n{content}\n"
        else:
            formatted = f"\n{content}\n"
        
        return formatted
