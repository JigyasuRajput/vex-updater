"""
Updater module - Main orchestrator that coordinates all operations in sequence.

This module implements the orchestrator pattern, acting as the explicit conductor that:
1. Calls scan_parser to load cve-bin-tool output
2. Calls vex_parser to load existing VEX file
3. Calls diff_engine to identify differences
4. Calls interactive_triage for user decisions
5. Calls vex_parser again to save updated VEX file
"""

import os
import json
from typing import Dict, List, Any, Optional
from .scan_parser import ScanParser
from .vex_parser import VEXParser
from .diff_engine import DiffEngine
from .interactive_triage import InteractiveTriage
from .interactive_triage import TriageSession
from .diff_engine import VulnerabilityDiffer


class VEXUpdater:
    """Main orchestrator for VEX updating operations."""
    
    def __init__(self):
        """Initialize the VEX updater with all necessary components."""
        self.scan_parser = ScanParser()
        self.vex_parser = VEXParser()
        self.diff_engine = DiffEngine()
        self.interactive_triage = InteractiveTriage()
    
    def update_vex_from_scan(self, scan_file: str, vex_file: str, 
                           output_file: Optional[str] = None,
                           interactive: bool = True,
                           default_decisions: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Main orchestration method to update VEX document from scan results.
        
        Args:
            scan_file: Path to scan output file (e.g., cve-bin-tool JSON)
            vex_file: Path to existing VEX document
            output_file: Path for updated VEX (optional, defaults to overwriting vex_file)
            interactive: Whether to use interactive triage
            default_decisions: Default decisions for batch processing
            
        Returns:
            Dictionary with update results and statistics
        """
        print("🚀 Starting VEX update process...")
        
        # Step 1: Load scan data
        print("📄 Loading scan data...")
        try:
            scan_data = self.scan_parser.load_cve_bin_tool_data(scan_file)
            scan_vulnerabilities = self.scan_parser.extract_vulnerabilities_from_scan(scan_data)
            print(f"   Found {len(scan_vulnerabilities)} vulnerabilities in scan")
        except Exception as e:
            raise ValueError(f"Failed to load scan data: {e}")
        
        # Step 2: Load existing VEX file
        print("📋 Loading existing VEX document...")
        try:
            vex_document = self.vex_parser.load_existing_vex(vex_file)
            vex_vulnerabilities = self.vex_parser.extract_vulnerabilities_from_vex(vex_document)
            print(f"   Found {len(vex_vulnerabilities)} vulnerabilities in VEX")
            print(f"   VEX format: {vex_document['format'].value}")
        except Exception as e:
            raise ValueError(f"Failed to load VEX document: {e}")
        
        # Step 3: Perform diff analysis
        print("🔍 Analyzing differences...")
        diff_result = self.diff_engine.compare_scan_with_vex(scan_vulnerabilities, vex_vulnerabilities)
        
        # Display summary
        print(self.diff_engine.get_diff_summary_text(diff_result))
        
        # Check if any changes are needed
        if (diff_result.summary['new'] == 0 and 
            diff_result.summary['removed'] == 0 and 
            diff_result.summary['updated'] == 0):
            print("✅ No updates needed. VEX document is current.")
            return {
                'status': 'no_changes',
                'summary': diff_result.summary,
                'output_file': vex_file
            }
        
        # Step 4: Triage decisions
        print("🤔 Getting triage decisions...")
        if interactive:
            triage_decisions = self.interactive_triage.run_interactive_triage(diff_result)
        else:
            if default_decisions is None:
                default_decisions = self._get_default_decisions()
            triage_decisions = self.interactive_triage.run_batch_triage(diff_result, default_decisions)
            # Fallback: if batch triage returns no decisions but there are new items and action is add/update
            if not triage_decisions:
                new_defaults = default_decisions.get('new', {'action': 'skip'})
                action = new_defaults.get('action', 'skip')
                if action in ('add', 'update'):
                    for d in self.diff_engine.get_actionable_items(diff_result):
                        if d.get('type') == 'new':
                            triage_decisions[d['vuln_id']] = {
                                'action': 'update',
                                'status': new_defaults.get('status', 'under_investigation'),
                                'justification': new_defaults.get('justification'),
                                'impact_statement': new_defaults.get('impact_statement')
                            }
        
        if not triage_decisions:
            print("ℹ️  No changes to apply.")
            return {
                'status': 'no_changes',
                'summary': diff_result.summary,
                'output_file': vex_file
            }
        
        # Step 5: Apply updates to VEX document
        print("💾 Applying updates to VEX document...")
        updated_vex_data = self._apply_triage_decisions(vex_document, triage_decisions)
        
        # Step 6: Save updated VEX document
        if output_file is None:
            output_file = vex_file  # Overwrite original file
        
        try:
            self.vex_parser.save_vex_document(updated_vex_data, output_file)
            print(f"✅ VEX document updated successfully: {output_file}")
        except Exception as e:
            # Bubble up permission errors directly
            if 'Permission denied' in str(e):
                raise PermissionError(str(e))
            raise ValueError(f"Failed to save updated VEX document: {e}")
        
        return {
            'status': 'success',
            'summary': diff_result.summary,
            'applied_changes': len(triage_decisions),
            'statistics': diff_result.summary,
            'output_file': output_file,
            'triage_decisions': triage_decisions
        }
    def create_vex_from_scan(self, scan_file: str, output_file: str,
                           interactive: bool = True,
                           vex_format: str = "cyclonedx") -> Dict[str, Any]:
        """
        Create a new VEX document from scan results.
        
        Args:sx
            scan_file: Path to scan output file
            output_file: Path for new VEX document
            interactive: Whether to use interactive triage
            vex_format: Format for new VEX document
            
        Returns:
            Dictionary with creation results
        """
        print("🆕 Creating new VEX document from scan...")
        
        # Load scan data
        print("📄 Loading scan data...")
        try:
            scan_data = self.scan_parser.load_cve_bin_tool_data(scan_file)
            scan_vulnerabilities = self.scan_parser.extract_vulnerabilities_from_scan(scan_data)
            print(f"   Found {len(scan_vulnerabilities)} vulnerabilities in scan")
        except Exception as e:
            raise ValueError(f"Failed to load scan data: {e}")
        
        if not scan_vulnerabilities:
            print("ℹ️  No vulnerabilities found in scan. Creating empty VEX document.")
            # TODO: Create minimal VEX document structure
            return {
                'status': 'created_empty',
                'output_file': output_file,
                'vulnerability_count': 0
            }
        
        # Create empty VEX structure for comparison
        empty_vex = {'data': {'vulnerabilities': []}, 'format': None}
        
        # Simulate diff to get all vulnerabilities as "new"
        diff_result = self.diff_engine.compare_scan_with_vex(scan_vulnerabilities, [])
        
        # Get triage decisions
        if interactive:
            triage_decisions = self.interactive_triage.run_interactive_triage(diff_result)
        else:
            default_decisions = self._get_default_decisions()
            triage_decisions = self.interactive_triage.run_batch_triage(diff_result, default_decisions)
        
        # Create new VEX document structure
        new_vex_data = self._create_new_vex_structure(scan_data, vex_format)
        
        # Create wrapper for consistency with update flow
        from .vex_parser import VEXFormat
        new_vex_document = {
            'data': new_vex_data,
            'format': VEXFormat.CYCLONEDX,  # Default for now
            'path': output_file
        }
        
        # Apply triage decisions
        updated_vex_data = self._apply_triage_decisions(new_vex_document, triage_decisions)
        
        # Save new VEX document
        try:
            self.vex_parser.save_vex_document(updated_vex_data, output_file)
            print(f"✅ New VEX document created successfully: {output_file}")
        except Exception as e:
            raise ValueError(f"Failed to save new VEX document: {e}")
        
        return {
            'status': 'created',
            'output_file': output_file,
            'vulnerability_count': len(triage_decisions),
            'triage_decisions': triage_decisions
        }
    
    def _apply_triage_decisions(self, vex_document: Dict[str, Any], 
                              triage_decisions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Apply triage decisions to update the VEX document."""
        # Always work with a document-shaped structure
        updated_document: Dict[str, Any] = {
            'data': vex_document.get('data', []).copy(),
            'format': vex_document.get('format'),
            'metadata': vex_document.get('metadata', {}),
            'product': vex_document.get('product', {})
        }
        
        for vuln_id, decision in triage_decisions.items():
            if decision['action'] == 'update':
                try:
                    updated_document = self.vex_parser.update_vex_vulnerability(
                        updated_document,
                        vuln_id,
                        decision['status'],
                        decision.get('justification'),
                        decision.get('impact_statement')
                    )
                    
                    print(f"   ✓ Updated {vuln_id} with status: {decision['status']}")
                    
                except Exception as e:
                    print(f"   ❌ Failed to update {vuln_id}: {e}")
        
        return updated_document
    
    def _create_new_vex_structure(self, scan_data: Dict[str, Any], vex_format: str) -> Dict[str, Any]:
        """Create a new VEX document structure."""
        # For now, create a minimal CycloneDX structure
        # TODO: Support other formats and more complete structure
        
        # Extract component information from scan
        components = []
        for comp_data in scan_data.get('components', []):
            component = {
                'type': 'library',
                'name': comp_data.get('name', 'unknown'),
                'version': comp_data.get('version', '0.0.0')
            }
            if comp_data.get('purl'):
                component['purl'] = comp_data['purl']
            components.append(component)
        
        vex_structure = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'serialNumber': f'urn:uuid:generated-{hash(str(scan_data))}',
            'version': 1,
            'components': components,
            'vulnerabilities': []
        }
        
        return vex_structure
    
    def _get_default_decisions(self) -> Dict[str, Dict[str, Any]]:
        """Get default triage decisions for batch processing."""
        return {
            'new': {
                'action': 'update',
                'status': 'under_investigation',
                'justification': None,
                'impact_statement': 'Newly discovered vulnerability requiring investigation.'
            },
            'removed': {
                'action': 'update',
                'status': 'fixed',
                'justification': None,
                'impact_statement': 'Vulnerability no longer detected in current scan.'
            }
        }
    
    def validate_inputs(self, scan_file: str, vex_file: Optional[str] = None) -> List[str]:
        """
        Validate input files before processing.
        
        Args:
            scan_file: Path to scan file
            vex_file: Path to VEX file (optional for new VEX creation)
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check scan file
        if not os.path.exists(scan_file):
            errors.append(f"Scan file not found: {scan_file}")
        else:
            try:
                self.scan_parser.load_cve_bin_tool_data(scan_file)
            except Exception as e:
                errors.append(f"Invalid scan file format: {e}")
        
        # Check VEX file if provided
        if vex_file:
            if not os.path.exists(vex_file):
                errors.append(f"VEX file not found: {vex_file}")
            else:
                try:
                    self.vex_parser.load_existing_vex(vex_file)
                except Exception as e:
                    errors.append(f"Invalid VEX file format: {e}")
        
        return errors
    
    def dry_run_update(self, scan_file: str, vex_file: str) -> Dict[str, Any]:
        """
        Perform a dry run to show what would be updated without making changes.
        
        Args:
            scan_file: Path to scan output file
            vex_file: Path to existing VEX document
            
        Returns:
            Dictionary with dry run results
        """
        print("🔍 Performing dry run analysis...")
        
        # Load scan data
        print("📄 Loading scan data...")
        scan_data = self.scan_parser.load_cve_bin_tool_data(scan_file)
        scan_vulnerabilities = self.scan_parser.extract_vulnerabilities_from_scan(scan_data)
        
        # Load existing VEX file
        print("📋 Loading existing VEX document...")
        vex_document = self.vex_parser.load_existing_vex(vex_file)
        vex_vulnerabilities = self.vex_parser.extract_vulnerabilities_from_vex(vex_document)
        
        # Perform diff analysis (simple summary)
        print("🔍 Analyzing differences...")
        diff_result = self.diff_engine.compare_scan_with_vex(scan_vulnerabilities, vex_vulnerabilities)

        # Derive enhanced summary fields expected by some callers
        enhanced_summary = diff_result.summary.copy()
        # Map to include keys used by enhanced tests
        enhanced_summary['existing'] = enhanced_summary.get('unchanged', 0) + enhanced_summary.get('updated', 0)
        enhanced_summary['stale'] = enhanced_summary.get('removed', 0)
        
        # Get actionable items
        actionable_items = self.diff_engine.get_actionable_items(diff_result)
        
        print("\n📋 DRY RUN RESULTS:")
        print("=" * 50)
        print(self.diff_engine.get_diff_summary_text(diff_result))
        
        if actionable_items:
            print("\n🎯 ACTIONABLE ITEMS (would be processed):")
            for i, item in enumerate(actionable_items, 1):
                print(f"\n{i}. {item['vuln_id']} ({item['priority']} priority)")
                print(f"   Type: {item['type']}")
                print(f"   Action: {item['action']}")
                print(f"   Description: {item['description']}")
        
        # Build a minimal diff_analysis/preview for compatibility
        diff_analysis = {
            'new': [d.vuln_id for d in diff_result.new_vulnerabilities],
            'removed': [d.vuln_id for d in diff_result.removed_vulnerabilities],
            'updated': [d.vuln_id for d in diff_result.updated_vulnerabilities],
            'unchanged': [d.vuln_id for d in diff_result.unchanged_vulnerabilities]
        }

        return {
            'status': 'dry_run_completed',
            'summary': enhanced_summary,
            'actionable_items': actionable_items,
            'diff_analysis': diff_analysis,
            'preview': actionable_items,
            'output_file': None
        }
    
    def show_diff_only(self, scan_file: str, vex_file: str) -> Dict[str, Any]:
        """
        Show only the diff without prompting for updates.
        
        Args:
            scan_file: Path to scan output file
            vex_file: Path to existing VEX document
            
        Returns:
            Dictionary with diff results
        """
        print("🔍 Showing diff analysis...")
        
        # Load scan data
        scan_data = self.scan_parser.load_cve_bin_tool_data(scan_file)
        scan_vulnerabilities = self.scan_parser.extract_vulnerabilities_from_scan(scan_data)
        
        # Load existing VEX file
        vex_document = self.vex_parser.load_existing_vex(vex_file)
        vex_vulnerabilities = self.vex_parser.extract_vulnerabilities_from_vex(vex_document)
        
        # Perform diff analysis
        diff_result = self.diff_engine.compare_scan_with_vex(scan_vulnerabilities, vex_vulnerabilities)
        
        print("\n📊 DIFF ANALYSIS:")
        print("=" * 50)
        print(self.diff_engine.get_diff_summary_text(diff_result))
        
        # Show detailed differences
        if diff_result.new_vulnerabilities:
            print("\n🆕 NEW VULNERABILITIES:")
            for diff in diff_result.new_vulnerabilities:
                print(f"  • {diff.vuln_id}")
                if diff.scan_info and 'component' in diff.scan_info:
                    comp = diff.scan_info['component']
                    print(f"    Component: {comp.get('name', 'unknown')} v{comp.get('version', 'unknown')}")
                print(f"    Action: {diff.recommended_action}")
        
        if diff_result.removed_vulnerabilities:
            print("\n🗑️  REMOVED VULNERABILITIES:")
            for diff in diff_result.removed_vulnerabilities:
                print(f"  • {diff.vuln_id}")
                print(f"    Action: {diff.recommended_action}")
        
        if diff_result.updated_vulnerabilities:
            print("\n🔄 VULNERABILITIES NEEDING REVIEW:")
            for diff in diff_result.updated_vulnerabilities:
                print(f"  • {diff.vuln_id}")
                print(f"    Action: {diff.recommended_action}")
        
        diff_analysis = {
            'new': [d.vuln_id for d in diff_result.new_vulnerabilities],
            'removed': [d.vuln_id for d in diff_result.removed_vulnerabilities],
            'updated': [d.vuln_id for d in diff_result.updated_vulnerabilities],
            'unchanged': [d.vuln_id for d in diff_result.unchanged_vulnerabilities]
        }

        enhanced_summary = diff_result.summary.copy()
        enhanced_summary['existing'] = enhanced_summary.get('unchanged', 0) + enhanced_summary.get('updated', 0)
        enhanced_summary['stale'] = enhanced_summary.get('removed', 0)

        recommendations = self.diff_engine.get_actionable_items(diff_result)

        return {
            'status': 'diff_shown',
            'summary': enhanced_summary,
            'diff_analysis': diff_analysis,
            'recommendations': recommendations,
            'output_file': None
        }
    
    def update_vex_from_scan_enhanced(self, scan_file: str, vex_file: str, 
                                    output_file: Optional[str] = None,
                                    interactive: bool = True,
                                    auto_skip_existing: bool = False) -> Dict[str, Any]:
        """
        Update VEX document from scan results with enhanced options.
        
        Args:
            scan_file: Path to scan output file
            vex_file: Path to existing VEX document
            output_file: Path for updated VEX (optional)
            interactive: Whether to use interactive triage
            auto_skip_existing: Don't prompt for vulnerabilities already in VEX
            
        Returns:
            Dictionary with update results
        """
        print("🚀 Starting enhanced VEX update process...")
        # Load scan data (raw)
        print("📄 Loading scan data...")
        scan_data = self.scan_parser.load_cve_bin_tool_data(scan_file)
        scan_vulnerabilities = self.scan_parser.extract_vulnerabilities_from_scan(scan_data)
        print(f"   Found {len(scan_vulnerabilities)} vulnerabilities in scan")

        # Load existing VEX document
        print("📋 Loading existing VEX document...")
        vex_document = self.vex_parser.load_existing_vex(vex_file)
        vex_vulnerabilities = self.vex_parser.extract_vulnerabilities_from_vex(vex_document)
        print(f"   Found {len(vex_vulnerabilities)} vulnerabilities in VEX")
        print(f"   VEX format: {vex_document['format'].value}")

        # Use simple diff for counts that align with tests
        print("🔍 Analyzing differences...")
        simple_diff = self.diff_engine.compare_scan_with_vex(scan_vulnerabilities, vex_vulnerabilities)
        print(self.diff_engine.get_diff_summary_text(simple_diff))

        # If nothing new or removed
        if simple_diff.summary.get('new', 0) == 0 and simple_diff.summary.get('removed', 0) == 0 and simple_diff.summary.get('updated', 0) == 0:
            print("ℹ️  No changes to apply.")
            return {
                'status': 'no_changes',
                'summary': simple_diff.summary,
                'output_file': vex_file
            }

        # Interactive triage for new vulns
        applied_changes = 0
        triage_decisions = {}
        if interactive:
            # Build component-level new vulnerabilities for triage session from simple diffs
            component_vulns = []
            from .diff_engine import ComponentVulnerability, VulnerabilityRecord
            for d in simple_diff.new_vulnerabilities:
                comp = (d.scan_info or {}).get('component', {})
                name = comp.get('name', 'unknown')
                version = comp.get('version', 'unknown')
                purl = comp.get('purl') or f"pkg:generic/{name}@{version}"
                record = VulnerabilityRecord(
                    cve_id=d.vuln_id,
                    component_name=name,
                    component_version=version,
                    component_purl=purl,
                    description=(d.scan_info or {}).get('description', ''),
                    severity=(d.scan_info or {}).get('severity', 'unknown')
                )
                component_vulns.append(ComponentVulnerability(vulnerability_record=record, component_identifier=purl))
            session = TriageSession(component_vulns, vex_document['format'])
            decisions = session.run_triage_session()
            for d in decisions:
                triage_decisions[d.cve_id] = {
                    'action': 'update',
                    'status': d.status,
                    'justification': d.justification,
                    'impact_statement': d.impact_statement
                }
        else:
            # Auto decisions: either skip existing or apply default to new
            defaults = self._get_default_decisions()
            if auto_skip_existing:
                # Only apply defaults to new vulnerabilities
                for d in simple_diff.new_vulnerabilities:
                    triage_decisions[d.vuln_id] = defaults['new']
            else:
                for d in simple_diff.new_vulnerabilities:
                    triage_decisions[d.vuln_id] = defaults['new']

        if not triage_decisions:
            print("ℹ️  No changes to apply.")
            return {
                'status': 'no_changes',
                'summary': simple_diff.summary,
                'output_file': vex_file
            }

        # Apply updates
        print("💾 Applying updates to VEX document...")
        updated_vex_data = vex_document
        for vuln_id, decision in triage_decisions.items():
            try:
                updated_vex_data = self.vex_parser.update_vex_vulnerability(
                    updated_vex_data,
                    vuln_id,
                    decision['status'],
                    decision.get('justification'),
                    decision.get('impact_statement')
                )
                applied_changes += 1
            except Exception as e:
                print(f"   ❌ Failed to update {vuln_id}: {e}")

        # Save
        if output_file is None:
            output_file = vex_file
        # Persist as raw CycloneDX for tests that expect 'vulnerabilities' at top-level
        if 'data' in updated_vex_data and isinstance(updated_vex_data['data'], list):
            raw_out = {
                'bomFormat': 'CycloneDX',
                'specVersion': '1.4',
                'serialNumber': updated_vex_data.get('metadata', {}).get('serialNumber', 'urn:uuid:generated'),
                'version': 1,
                'vulnerabilities': updated_vex_data['data']
            }
            self.vex_parser.save_vex_document(raw_out, output_file)
        else:
            self.vex_parser.save_vex_document(updated_vex_data, output_file)

        return {
            'status': 'success',
            'summary': simple_diff.summary,
            'applied_changes': applied_changes,
            'output_file': output_file
        }
