"""
Diff Engine module - Core comparison logic between scan reports and VEX files.
"""

from typing import Dict, List, Any, Set, Optional, Tuple
from dataclasses import dataclass


@dataclass
class VulnerabilityRecord:
    """Enhanced vulnerability record with component details."""
    cve_id: str
    component_name: str
    component_version: str
    component_purl: str
    description: str
    severity: str


@dataclass
class ComponentVulnerability:
    """Combines vulnerability record with component identifier."""
    vulnerability_record: VulnerabilityRecord
    component_identifier: str


@dataclass
class VulnerabilityDiffResult:
    """Container for enhanced diff analysis results."""
    new_vulns: List[ComponentVulnerability]
    existing_vulns: List[ComponentVulnerability]
    stale_vulns: List[ComponentVulnerability]
    summary: Dict[str, int]


class VulnerabilityDiffer:
    """Enhanced granular comparison logic between scan reports and VEX files."""
    
    def __init__(self, scan_report_data: Dict[str, Any], vex_document_data: Dict[str, Any]):
        """
        Initialize the VulnerabilityDiffer with scan and VEX data.
        
        Args:
            scan_report_data: Vulnerability scan report data
            vex_document_data: Existing VEX document data
        """
        self.scan_data = scan_report_data
        self.vex_data = vex_document_data
        self.scan_vulns = self._extract_vulnerabilities_from_scan()
        self.vex_vulns = self._extract_vulnerabilities_from_vex()
    
    def _extract_vulnerabilities_from_scan(self) -> List[ComponentVulnerability]:
        """Extract vulnerabilities from scan data with component information."""
        vulns = []
        
        # Handle different scan data formats
        if 'vulnerabilities' in self.scan_data:
            scan_vulns = self.scan_data['vulnerabilities']
        elif 'results' in self.scan_data:
            scan_vulns = self.scan_data['results']
        else:
            scan_vulns = self.scan_data.get('data', [])
        
        for vuln in scan_vulns:
            cve_id = vuln.get('cve_id') or vuln.get('id') or vuln.get('vulnerability_id')
            if not cve_id:
                continue
                
            # Extract component information
            component = vuln.get('component', {})
            component_name = component.get('name', 'unknown')
            component_version = component.get('version', 'unknown')
            component_purl = component.get('purl', '')
            
            # If no PURL, create a basic identifier
            if not component_purl:
                component_purl = f"pkg:generic/{component_name}@{component_version}"
            
            # Create composite identifier
            component_identifier = component_purl
            
            vuln_record = VulnerabilityRecord(
                cve_id=cve_id,
                component_name=component_name,
                component_version=component_version,
                component_purl=component_purl,
                description=vuln.get('description', ''),
                severity=vuln.get('severity', 'unknown')
            )
            
            vulns.append(ComponentVulnerability(
                vulnerability_record=vuln_record,
                component_identifier=component_identifier
            ))
        
        return vulns
    
    def _extract_vulnerabilities_from_vex(self) -> List[ComponentVulnerability]:
        """Extract vulnerabilities from VEX data with component information."""
        vulns = []
        
        # Navigate VEX structure to find vulnerabilities
        vex_vulns = []
        if 'vulnerabilities' in self.vex_data:
            vex_vulns = self.vex_data['vulnerabilities']
        elif 'product_tree' in self.vex_data and 'branches' in self.vex_data['product_tree']:
            # Handle nested VEX structure
            for branch in self.vex_data['product_tree']['branches']:
                if 'vulnerabilities' in branch:
                    vex_vulns.extend(branch['vulnerabilities'])
        
        for vuln in vex_vulns:
            # Handle both 'id' and 'cve' fields for CVE ID
            cve_id = vuln.get('id') or vuln.get('cve') or vuln.get('cve_id')
            if not cve_id:
                continue
            
            # Extract component information from VEX affects field or product
            components_affected = []
            
            # Handle CycloneDX format
            if 'affects' in vuln:
                for affect in vuln['affects']:
                    component_purl = affect.get('ref', '')
                    if component_purl:
                        components_affected.append(component_purl)
            
            # Handle CSAF format
            elif 'product_status' in vuln:
                for status_key, product_ids in vuln['product_status'].items():
                    if isinstance(product_ids, list):
                        # For CSAF, we need to map product_ids to PURLs
                        # For now, create generic PURLs
                        for product_id in product_ids:
                            components_affected.append(f"pkg:generic/{product_id}@unknown")
            
            # If no specific components found, create a generic one
            if not components_affected:
                components_affected = [f"pkg:generic/unknown@unknown"]
            
            # Create ComponentVulnerability for each affected component
            for component_purl in components_affected:
                # Parse component info from PURL
                component_name = 'unknown'
                component_version = 'unknown'
                
                if component_purl.startswith('pkg:'):
                    try:
                        # Simple PURL parsing: pkg:type/name@version
                        parts = component_purl.replace('pkg:', '').split('/')
                        if len(parts) >= 2:
                            name_version = parts[-1]
                            if '@' in name_version:
                                component_name, component_version = name_version.split('@', 1)
                            else:
                                component_name = name_version
                    except:
                        pass  # Keep default values
                
                vuln_record = VulnerabilityRecord(
                    cve_id=cve_id,
                    component_name=component_name,
                    component_version=component_version,
                    component_purl=component_purl,
                    description=vuln.get('description', ''),
                    severity=vuln.get('severity', 'unknown')
                )
                
                vulns.append(ComponentVulnerability(
                    vulnerability_record=vuln_record,
                    component_identifier=component_purl
                ))
        
        return vulns
    
    def find_new_vulnerabilities(self) -> List[ComponentVulnerability]:
        """Find CVEs in scan but not in VEX."""
        scan_keys = {(v.vulnerability_record.cve_id, v.component_identifier) for v in self.scan_vulns}
        vex_keys = {(v.vulnerability_record.cve_id, v.component_identifier) for v in self.vex_vulns}
        
        new_keys = scan_keys - vex_keys
        return [v for v in self.scan_vulns 
                if (v.vulnerability_record.cve_id, v.component_identifier) in new_keys]
    
    def find_existing_vulnerabilities(self) -> List[ComponentVulnerability]:
        """Find CVEs in both scan and VEX."""
        scan_keys = {(v.vulnerability_record.cve_id, v.component_identifier) for v in self.scan_vulns}
        vex_keys = {(v.vulnerability_record.cve_id, v.component_identifier) for v in self.vex_vulns}
        
        common_keys = scan_keys & vex_keys
        return [v for v in self.scan_vulns 
                if (v.vulnerability_record.cve_id, v.component_identifier) in common_keys]
    
    def find_stale_vulnerabilities(self) -> List[ComponentVulnerability]:
        """Find CVEs in VEX but not in scan."""
        scan_keys = {(v.vulnerability_record.cve_id, v.component_identifier) for v in self.scan_vulns}
        vex_keys = {(v.vulnerability_record.cve_id, v.component_identifier) for v in self.vex_vulns}
        
        stale_keys = vex_keys - scan_keys
        return [v for v in self.vex_vulns 
                if (v.vulnerability_record.cve_id, v.component_identifier) in stale_keys]
    
    def get_vulnerability_details(self, cve_id: str, component_identifier: str) -> Optional[ComponentVulnerability]:
        """Get component and vulnerability info for a specific CVE-component combination."""
        for vuln in self.scan_vulns + self.vex_vulns:
            if (vuln.vulnerability_record.cve_id == cve_id and 
                vuln.component_identifier == component_identifier):
                return vuln
        return None
    
    def analyze(self) -> VulnerabilityDiffResult:
        """Perform complete analysis and return VulnerabilityDiffResult."""
        new_vulns = self.find_new_vulnerabilities()
        existing_vulns = self.find_existing_vulnerabilities()
        stale_vulns = self.find_stale_vulnerabilities()
        
        summary = {
            "new": len(new_vulns),
            "existing": len(existing_vulns),
            "stale": len(stale_vulns),
            "total_scan": len(self.scan_vulns),
            "total_vex": len(self.vex_vulns)
        }
        
        return VulnerabilityDiffResult(
            new_vulns=new_vulns,
            existing_vulns=existing_vulns,
            stale_vulns=stale_vulns,
            summary=summary
        )


@dataclass
class VulnerabilityDiff:
    """Represents a difference between scan and VEX data for a vulnerability."""
    vuln_id: str
    status: str  # "new", "updated", "removed", "unchanged"
    scan_info: Optional[Dict[str, Any]] = None
    vex_info: Optional[Dict[str, Any]] = None
    recommended_action: str = ""
    description: str = ""


@dataclass
class DiffResult:
    """Container for diff analysis results."""
    new_vulnerabilities: List[VulnerabilityDiff]
    updated_vulnerabilities: List[VulnerabilityDiff]
    removed_vulnerabilities: List[VulnerabilityDiff]
    unchanged_vulnerabilities: List[VulnerabilityDiff]
    summary: Dict[str, int]


class DiffEngine:
    """Core comparison logic between scan reports and VEX files."""
    
    def __init__(self):
        """Initialize the diff engine."""
        pass
    
    def compare_scan_with_vex(self, scan_vulnerabilities: List[Dict[str, Any]], 
                             vex_vulnerabilities: List[Dict[str, Any]]) -> DiffResult:
        """
        Compare vulnerabilities from scan data with those in VEX document.
        
        Args:
            scan_vulnerabilities: List of vulnerabilities from scan data
            vex_vulnerabilities: List of vulnerabilities from VEX document
            
        Returns:
            DiffResult containing categorized differences
        """
        # Create sets for easier comparison
        scan_vuln_ids = {vuln.get('vuln_id') for vuln in scan_vulnerabilities if vuln.get('vuln_id')}
        vex_vuln_ids = {vuln.get('id') for vuln in vex_vulnerabilities if vuln.get('id')}
        
        # Create mappings for quick lookup
        scan_vuln_map = {vuln.get('vuln_id'): vuln for vuln in scan_vulnerabilities if vuln.get('vuln_id')}
        vex_vuln_map = {vuln.get('id'): vuln for vuln in vex_vulnerabilities if vuln.get('id')}
        
        # Find different categories
        new_vuln_ids = scan_vuln_ids - vex_vuln_ids
        removed_vuln_ids = vex_vuln_ids - scan_vuln_ids
        common_vuln_ids = scan_vuln_ids & vex_vuln_ids
        
        # Create diff objects
        new_vulnerabilities = []
        updated_vulnerabilities = []
        removed_vulnerabilities = []
        unchanged_vulnerabilities = []
        
        # Process new vulnerabilities
        for vuln_id in new_vuln_ids:
            scan_info = scan_vuln_map.get(vuln_id)
            diff = VulnerabilityDiff(
                vuln_id=vuln_id,
                status="new",
                scan_info=scan_info,
                vex_info=None,
                recommended_action="Add to VEX with appropriate status",
                description=f"New vulnerability {vuln_id} found in scan but not in VEX"
            )
            new_vulnerabilities.append(diff)
        
        # Process removed vulnerabilities
        for vuln_id in removed_vuln_ids:
            vex_info = vex_vuln_map.get(vuln_id)
            diff = VulnerabilityDiff(
                vuln_id=vuln_id,
                status="removed",
                scan_info=None,
                vex_info=vex_info,
                recommended_action="Consider removing from VEX or marking as fixed",
                description=f"Vulnerability {vuln_id} exists in VEX but not found in current scan"
            )
            removed_vulnerabilities.append(diff)
        
        # Process common vulnerabilities (check for updates)
        for vuln_id in common_vuln_ids:
            scan_info = scan_vuln_map.get(vuln_id)
            vex_info = vex_vuln_map.get(vuln_id)
            
            # Check if VEX entry needs updates
            needs_update = self._analyze_vulnerability_changes(scan_info, vex_info)
            
            if needs_update:
                diff = VulnerabilityDiff(
                    vuln_id=vuln_id,
                    status="updated",
                    scan_info=scan_info,
                    vex_info=vex_info,
                    recommended_action="Review and update VEX status if needed",
                    description=f"Vulnerability {vuln_id} exists in both but may need status update"
                )
                updated_vulnerabilities.append(diff)
            else:
                diff = VulnerabilityDiff(
                    vuln_id=vuln_id,
                    status="unchanged",
                    scan_info=scan_info,
                    vex_info=vex_info,
                    recommended_action="No action needed",
                    description=f"Vulnerability {vuln_id} is current and properly documented"
                )
                unchanged_vulnerabilities.append(diff)
        
        # Create summary
        summary = {
            "new": len(new_vulnerabilities),
            "updated": len(updated_vulnerabilities),
            "removed": len(removed_vulnerabilities),
            "unchanged": len(unchanged_vulnerabilities),
            "total_scan": len(scan_vulnerabilities),
            "total_vex": len(vex_vulnerabilities)
        }
        
        return DiffResult(
            new_vulnerabilities=new_vulnerabilities,
            updated_vulnerabilities=updated_vulnerabilities,
            removed_vulnerabilities=removed_vulnerabilities,
            unchanged_vulnerabilities=unchanged_vulnerabilities,
            summary=summary
        )
    
    def _analyze_vulnerability_changes(self, scan_info: Dict[str, Any], 
                                     vex_info: Dict[str, Any]) -> bool:
        """
        Analyze if a vulnerability that exists in both scan and VEX needs updates.
        
        Args:
            scan_info: Vulnerability info from scan
            vex_info: Vulnerability info from VEX
            
        Returns:
            True if the VEX entry likely needs updates
        """
        # If VEX has no status information, it needs to be updated
        vex_status = vex_info.get('status')
        if not vex_status:
            return True
        
        # If VEX status is "under_investigation", it might need review
        if vex_status == "under_investigation":
            return True
        
        # Check if component version has changed significantly
        scan_component = scan_info.get('component', {})
        scan_version = scan_component.get('version', '')
        
        # For now, we consider any common vulnerability as potentially needing review
        # In a more sophisticated implementation, we could:
        # - Compare component versions
        # - Check timestamps
        # - Analyze severity changes
        # - Look for patch availability
        
        return False  # Conservative approach - don't auto-suggest updates for existing entries
    
    def get_diff_summary_text(self, diff_result: DiffResult) -> str:
        """Generate a human-readable summary of the diff results."""
        summary = diff_result.summary
        
        text = f"VEX Update Analysis Summary:\n"
        text += f"=" * 40 + "\n"
        
        # Only include total counts if they exist in summary
        if 'total_scan' in summary:
            text += f"📊 Total vulnerabilities in scan: {summary['total_scan']}\n"
        if 'total_vex' in summary:
            text += f"📋 Total vulnerabilities in VEX: {summary['total_vex']}\n"
        text += "\n"
        
        if summary['new'] > 0:
            text += f"🆕 New vulnerabilities to add: {summary['new']}\n"
        
        if summary['updated'] > 0:
            text += f"🔄 Vulnerabilities needing review: {summary['updated']}\n"
        
        if summary['removed'] > 0:
            text += f"🗑️  Vulnerabilities no longer in scan: {summary['removed']}\n"
        
        if summary['unchanged'] > 0:
            text += f"✅ Vulnerabilities up to date: {summary['unchanged']}\n"
        
        return text
    
    def get_actionable_items(self, diff_result: DiffResult) -> List[Dict[str, Any]]:
        """
        Get a prioritized list of actionable items from the diff results.
        
        Returns:
            List of actionable items sorted by priority
        """
        actionable_items = []
        
        # High priority: New vulnerabilities
        for diff in diff_result.new_vulnerabilities:
            actionable_items.append({
                'priority': 'high',
                'type': 'new',
                'vuln_id': diff.vuln_id,
                'action': diff.recommended_action,
                'description': diff.description,
                'scan_info': diff.scan_info
            })
        
        # Medium priority: Removed vulnerabilities
        for diff in diff_result.removed_vulnerabilities:
            actionable_items.append({
                'priority': 'medium',
                'type': 'removed',
                'vuln_id': diff.vuln_id,
                'action': diff.recommended_action,
                'description': diff.description,
                'vex_info': diff.vex_info
            })
        
        # Low priority: Vulnerabilities needing review
        for diff in diff_result.updated_vulnerabilities:
            actionable_items.append({
                'priority': 'low',
                'type': 'review',
                'vuln_id': diff.vuln_id,
                'action': diff.recommended_action,
                'description': diff.description,
                'scan_info': diff.scan_info,
                'vex_info': diff.vex_info
            })
        
        # Sort by priority (high, medium, low)
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        actionable_items.sort(key=lambda x: priority_order.get(x['priority'], 3))
        
        return actionable_items
