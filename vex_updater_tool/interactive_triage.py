"""
Interactive Triage module - Enhanced user interaction for triaging vulnerabilities.

Phase 1 Implementation: Rock-solid single-vulnerability triage loop with enhanced
component-specific context and smart prompting based on VEX format capabilities.
"""

import sys
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from .vex_parser import VEXStatus, VEXJustification, VEXFormat
from .diff_engine import VulnerabilityDiffer, ComponentVulnerability, VulnerabilityDiffResult


@dataclass
class VulnerabilityStatement:
    """Represents a triage decision for a component-vulnerability pair."""
    cve_id: str
    component_identifier: str
    status: VEXStatus
    justification: Optional[VEXJustification] = None
    impact_statement: Optional[str] = None
    notes: Optional[str] = None


class TriageSession:
    """Enhanced interactive triage session with component-specific context."""
    
    def __init__(self, new_vulnerabilities: List[ComponentVulnerability], vex_format: VEXFormat):
        """
        Initialize a triage session.
        
        Args:
            new_vulnerabilities: List of new component-vulnerability pairs to triage
            vex_format: Target VEX format for status/justification options
        """
        self.new_vulnerabilities = new_vulnerabilities
        self.vex_format = vex_format
        self.current_index = 0
        self.total_count = len(new_vulnerabilities)
        self.decisions: List[VulnerabilityStatement] = []
        
        # Format-specific status and justification options
        self.valid_statuses = self._get_format_statuses()
        self.valid_justifications = self._get_format_justifications()
    
    def _get_format_statuses(self) -> List[VEXStatus]:
        """Get status options based on VEX format."""
        base_statuses = [
            VEXStatus.NOT_AFFECTED,
            VEXStatus.AFFECTED,
            VEXStatus.FIXED,
            VEXStatus.UNDER_INVESTIGATION
        ]
        
        # Format-specific adjustments could be added here
        if self.vex_format == VEXFormat.CSAF:
            # CSAF might have additional statuses
            pass
        elif self.vex_format == VEXFormat.OPENVEX:
            # OpenVEX might have different status names
            pass
        
        return base_statuses
    
    def _get_format_justifications(self) -> List[VEXJustification]:
        """Get justification options based on VEX format."""
        base_justifications = [
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST
        ]
        
        # Format-specific adjustments could be added here
        return base_justifications
    
    def run_triage_session(self) -> List[VulnerabilityStatement]:
        """
        Run the complete triage session.
        
        Returns:
            List of VulnerabilityStatement objects representing triage decisions
        """
        if not self.new_vulnerabilities:
            print("✅ No new vulnerabilities to triage.")
            return []
        
        print("🔍 VEX Updater - Interactive Triage Session")
        print("=" * 60)
        print(f"📋 Format: {self.vex_format.value.upper()}")
        print(f"📊 Total component-vulnerability pairs to triage: {self.total_count}")
        print()
        
        for i, component_vuln in enumerate(self.new_vulnerabilities, 1):
            print(f"Progress: {i}/{self.total_count}")
            print("-" * 40)
            
            decision = self.triage_single_vulnerability(component_vuln)
            if decision:
                self.decisions.append(decision)
            
            print()  # Add spacing between vulnerabilities
        
        print("✅ Triage session completed!")
        print(f"📝 Decisions made: {len(self.decisions)}/{self.total_count}")
        
        return self.decisions
    
    def triage_single_vulnerability(self, component_vuln: ComponentVulnerability) -> Optional[VulnerabilityStatement]:
        """
        Triage a single component-vulnerability pair.
        
        Args:
            component_vuln: ComponentVulnerability object to triage
            
        Returns:
            VulnerabilityStatement with triage decision, or None if skipped
        """
        self.display_vulnerability_info(component_vuln)
        
        # Get user choice for action
        while True:
            choice = input("\nAction: [t]riage, [s]kip, [q]uit: ").strip().lower()
            
            if choice in ['t', 'triage']:
                return self._get_vulnerability_statement(component_vuln)
            elif choice in ['s', 'skip']:
                print(f"⏭️  Skipping {component_vuln.vulnerability_record.cve_id}")
                return None
            elif choice in ['q', 'quit']:
                print("👋 Exiting triage session...")
                sys.exit(0)
                return None  # This line won't be reached normally, but helps with testing
            else:
                print("❌ Invalid choice. Please enter 't', 's', or 'q'.")
    
    def display_vulnerability_info(self, component_vuln: ComponentVulnerability) -> None:
        """
        Display comprehensive vulnerability information with component context.
        
        Args:
            component_vuln: ComponentVulnerability object to display
        """
        record = component_vuln.vulnerability_record
        
        print(f"🔍 CVE: {record.cve_id}")
        print(f"📦 Component: {record.component_name} v{record.component_version}")
        print(f"🔗 PURL: {record.component_purl}")
        print(f"⚠️  Severity: {record.severity.upper()}")
        
        if record.description:
            # Truncate long descriptions for better display
            desc = record.description
            if len(desc) > 100:
                desc = desc[:97] + "..."
            print(f"📝 Description: {desc}")
        
        # Show component-specific context
        print(f"🎯 This CVE affects the specific component: {record.component_name}")
        print(f"   (Other components may be affected by the same CVE)")
    
    def _get_vulnerability_statement(self, component_vuln: ComponentVulnerability) -> VulnerabilityStatement:
        """
        Get complete vulnerability statement from user input.
        
        Args:
            component_vuln: ComponentVulnerability object to triage
            
        Returns:
            VulnerabilityStatement with user decisions
        """
        record = component_vuln.vulnerability_record
        
        print(f"\n🔍 Triaging {record.cve_id} for {record.component_name}")
        print("-" * 50)
        
        # Get status
        status = self.prompt_for_status()
        
        # Get justification if required
        justification = None
        if status == VEXStatus.NOT_AFFECTED:
            justification = self.prompt_for_justification(status)
        
        # Get impact statement
        impact_statement = self.prompt_for_impact_statement()
        
        # Get optional notes
        notes = self._get_optional_notes()
        
        return VulnerabilityStatement(
            cve_id=record.cve_id,
            component_identifier=component_vuln.component_identifier,
            status=status,
            justification=justification,
            impact_statement=impact_statement,
            notes=notes
        )
    
    def prompt_for_status(self) -> VEXStatus:
        """
        Prompt user for VEX status with format-specific options.
        
        Returns:
            Selected VEXStatus
        """
        print(f"\n📋 VEX Status Options ({self.vex_format.value.upper()}):")
        for i, status in enumerate(self.valid_statuses, 1):
            print(f"  {i}. {status}")
        
        while True:
            try:
                choice = input(f"\nSelect status (1-{len(self.valid_statuses)}): ").strip()
                index = int(choice) - 1
                if 0 <= index < len(self.valid_statuses):
                    selected_status = self.valid_statuses[index]
                    print(f"✅ Selected: {selected_status}")
                    return selected_status
                else:
                    print(f"❌ Invalid choice. Please enter a number 1-{len(self.valid_statuses)}.")
            except ValueError:
                print(f"❌ Invalid input. Please enter a number 1-{len(self.valid_statuses)}.")
    
    def prompt_for_justification(self, status: VEXStatus) -> VEXJustification:
        """
        Prompt user for justification when status is NOT_AFFECTED.
        
        Args:
            status: The selected VEX status
            
        Returns:
            Selected VEXJustification
        """
        if status != VEXStatus.NOT_AFFECTED:
            return None
        
        print(f"\n📋 Justification Required for '{status}' ({self.vex_format.value.upper()}):")
        for i, justification in enumerate(self.valid_justifications, 1):
            print(f"  {i}. {justification}")
        
        while True:
            try:
                choice = input(f"\nSelect justification (1-{len(self.valid_justifications)}): ").strip()
                index = int(choice) - 1
                if 0 <= index < len(self.valid_justifications):
                    selected_justification = self.valid_justifications[index]
                    print(f"✅ Selected: {selected_justification}")
                    return selected_justification
                else:
                    print(f"❌ Invalid choice. Please enter a number 1-{len(self.valid_justifications)}.")
            except ValueError:
                print(f"❌ Invalid input. Please enter a number 1-{len(self.valid_justifications)}.")
    
    def prompt_for_impact_statement(self) -> Optional[str]:
        """
        Prompt user for optional impact statement.
        
        Returns:
            Impact statement string or None
        """
        print(f"\n📝 Impact Statement (optional):")
        print("   Provide additional context about the vulnerability's impact on this component.")
        print("   Press Enter to skip.")
        
        statement = input("Impact statement: ").strip()
        if statement:
            print(f"✅ Impact statement recorded: {statement[:50]}{'...' if len(statement) > 50 else ''}")
        else:
            print("⏭️  No impact statement provided.")
        
        return statement if statement else None
    
    def _get_optional_notes(self) -> Optional[str]:
        """
        Get optional notes from user.
        
        Returns:
            Notes string or None
        """
        print(f"\n📝 Additional Notes (optional):")
        print("   Add any additional context or notes about this triage decision.")
        print("   Press Enter to skip.")
        
        notes = input("Notes: ").strip()
        if notes:
            print(f"✅ Notes recorded: {notes[:50]}{'...' if len(notes) > 50 else ''}")
        else:
            print("⏭️  No notes provided.")
        
        return notes if notes else None


# Compatibility - keep the old InteractiveTriage class for backward compatibility
class InteractiveTriage:
    """Interactive triage class for compatibility."""
    
    def __init__(self):
        """Initialize the interactive triage system."""
        self.valid_statuses = [
            VEXStatus.NOT_AFFECTED,
            VEXStatus.AFFECTED,
            VEXStatus.FIXED,
            VEXStatus.UNDER_INVESTIGATION
        ]
        
        self.valid_justifications = [
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST
        ]
    
    def run_interactive_triage(self, diff_result: Any) -> Dict[str, Dict[str, Any]]:
        """
        Method for compatibility.
        
        Args:
            diff_result: Results from diff analysis
            
        Returns:
            Dictionary mapping vuln_id to triage decisions
        """
        print("⚠️  Using alternative InteractiveTriage. Consider upgrading to TriageSession.")
        
        # Convert to new format if possible
        if hasattr(diff_result, 'new_vulns'):
            # New VulnerabilityDiffResult format
            new_vulns = diff_result.new_vulns
            vex_format = VEXFormat.CYCLONEDX  # Default format
            
            session = TriageSession(new_vulns, vex_format)
            decisions = session.run_triage_session()
            
            # Convert back to alternative format
            alternative_decisions = {}
            for decision in decisions:
                alternative_decisions[decision.cve_id] = {
                    'action': 'update',
                    'status': decision.status,
                    'justification': decision.justification,
                    'impact_statement': decision.impact_statement
                }
            
            return alternative_decisions
        else:
            # Fallback for old format
            return self._alternative_triage(diff_result)
    
    def _alternative_triage(self, diff_result: Any) -> Dict[str, Dict[str, Any]]:
        """Basic triage implementation."""
        print("⚠️  Basic triage mode - limited functionality")
        return {}
    
    def run_batch_triage(self, diff_result: Any, 
                        default_decisions: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Basic batch triage method.
        
        Args:
            diff_result: Results from diff analysis
            default_decisions: Default decisions for different types
            
        Returns:
            Dictionary mapping vuln_id to triage decisions
        """
        print("⚠️  Using alternative batch triage. Consider upgrading to TriageSession.")
        decisions: Dict[str, Dict[str, Any]] = {}
        # Support alternative DiffResult with new_vulnerabilities
        new_items = []
        if hasattr(diff_result, 'new_vulnerabilities'):
            new_items = getattr(diff_result, 'new_vulnerabilities') or []
        elif isinstance(diff_result, dict) and 'new' in diff_result:
            new_items = diff_result.get('new', [])

        new_defaults = default_decisions.get('new', {'action': 'skip'})
        for item in new_items:
            vuln_id = getattr(item, 'vuln_id', None) or item.get('vuln_id') if isinstance(item, dict) else None
            if not vuln_id:
                continue
            action = new_defaults.get('action', 'skip')
            if action == 'skip':
                continue
            # Normalize to update action for updater application
            decision = {
                'action': 'update',
                'status': new_defaults.get('status', VEXStatus.UNDER_INVESTIGATION),
                'justification': new_defaults.get('justification'),
                'impact_statement': new_defaults.get('impact_statement')
            }
            decisions[vuln_id] = decision

        return decisions
