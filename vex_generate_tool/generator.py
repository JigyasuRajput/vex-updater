"""
VEX Generator - Core logic for generating VEX documents in CycloneDX format.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from cyclonedx.model import bom, component, vulnerability
from cyclonedx.model.vulnerability import ImpactAnalysisState, ImpactAnalysisJustification
from cyclonedx.output.json import JsonV1Dot4


class VEXStatus:
    """Valid VEX status values."""
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VEXJustification:
    """Valid VEX justification values for not_affected status."""
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class VEXGenerator:
    """Generates VEX documents in CycloneDX JSON format."""
    
    VALID_STATUSES = {
        VEXStatus.NOT_AFFECTED,
        VEXStatus.AFFECTED,
        VEXStatus.FIXED,
        VEXStatus.UNDER_INVESTIGATION
    }
    
    VALID_JUSTIFICATIONS = {
        VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
        VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
        VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST
    }
    
    def __init__(self):
        """Initialize the VEX generator."""
        pass
    
    def validate_status(self, status: str) -> None:
        """Validate VEX status value."""
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(self.VALID_STATUSES)}")
    
    def validate_justification(self, justification: str) -> None:
        """Validate VEX justification value."""
        if justification not in self.VALID_JUSTIFICATIONS:
            raise ValueError(f"Invalid justification '{justification}'. Must be one of: {', '.join(self.VALID_JUSTIFICATIONS)}")
    
    def load_cve_bin_tool_data(self, file_path: str) -> Dict[str, Any]:
        """Load and parse cve-bin-tool JSON output."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Validate basic structure
            if not isinstance(data, dict):
                raise ValueError("Input JSON must be a dictionary")
            
            if 'components' not in data:
                raise ValueError("Input JSON must contain 'components' field")
            
            if not isinstance(data['components'], list):
                raise ValueError("'components' field must be a list")
            
            return data
        
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {file_path}")
        except Exception as e:
            raise ValueError(f"Error reading input file: {e}")
    
    def find_component_with_vulnerability(self, data: Dict[str, Any], vuln_id: str) -> Optional[Dict[str, Any]]:
        """Find the component that contains the specified vulnerability."""
        for comp in data.get('components', []):
            if 'vulnerabilities' in comp:
                for vuln in comp['vulnerabilities']:
                    if vuln.get('vuln_id') == vuln_id:
                        return comp
        return None
    
    def create_cyclonedx_component(self, comp_data: Dict[str, Any]) -> component.Component:
        """Create a CycloneDX component from component data."""
        comp_name = comp_data.get('name', 'unknown')
        comp_version = comp_data.get('version', '0.0.0')
        comp_purl = comp_data.get('purl')
        
        # Create component
        comp = component.Component(
            name=comp_name,
            version=comp_version,
            type=component.ComponentType.LIBRARY
        )
        
        if comp_purl:
            from packageurl import PackageURL
            try:
                purl_obj = PackageURL.from_string(comp_purl)
                comp.purl = purl_obj
            except Exception:
                # If PURL parsing fails, continue without it
                pass
        
        return comp
    
    def create_vex_vulnerability(self, vuln_id: str, status: str, justification: Optional[str] = None, 
                               impact_statement: Optional[str] = None) -> vulnerability.Vulnerability:
        """Create a VEX vulnerability entry."""
        # Validate inputs
        self.validate_status(status)
        if justification:
            self.validate_justification(justification)
        
        # Create vulnerability source
        vuln_source = vulnerability.VulnerabilitySource(
            name="NVD",
            url=f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
        )
        
        # Create vulnerability
        vuln = vulnerability.Vulnerability(
            id=vuln_id,
            source=vuln_source
        )
        
        # Create VEX analysis
        analysis = vulnerability.VulnerabilityAnalysis(
            state=self._map_status_to_analysis_state(status),
            justification=self._map_justification_to_analysis_justification(justification) if justification else None,
            detail=impact_statement
        )
        
        vuln.analysis = analysis
        
        return vuln
    
    def _map_status_to_analysis_state(self, status: str) -> ImpactAnalysisState:
        """Map VEX status to CycloneDX vulnerability analysis state."""
        mapping = {
            VEXStatus.NOT_AFFECTED: ImpactAnalysisState.NOT_AFFECTED,
            VEXStatus.AFFECTED: ImpactAnalysisState.EXPLOITABLE,
            VEXStatus.FIXED: ImpactAnalysisState.RESOLVED,
            VEXStatus.UNDER_INVESTIGATION: ImpactAnalysisState.IN_TRIAGE
        }
        return mapping[status]
    
    def _map_justification_to_analysis_justification(self, justification: str) -> ImpactAnalysisJustification:
        """Map VEX justification to CycloneDX vulnerability analysis justification."""
        mapping = {
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT: ImpactAnalysisJustification.CODE_NOT_PRESENT,
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: ImpactAnalysisJustification.CODE_NOT_REACHABLE,
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: ImpactAnalysisJustification.REQUIRES_CONFIGURATION,
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST: ImpactAnalysisJustification.REQUIRES_DEPENDENCY
        }
        return mapping[justification]
    
    def generate_vex_document(self, cve_bin_data: Dict[str, Any], vuln_id: str, status: str, 
                            justification: Optional[str] = None, impact_statement: Optional[str] = None) -> str:
        """Generate a complete VEX document in CycloneDX JSON format."""
        # Find the component with the specified vulnerability
        comp_data = self.find_component_with_vulnerability(cve_bin_data, vuln_id)
        if not comp_data:
            raise ValueError(f"Vulnerability {vuln_id} not found in any component")
        
        # Create CycloneDX BOM
        bom_obj = bom.Bom()
        bom_obj.serial_number = uuid.uuid4()  # Use UUID object instead of string
        bom_obj.version = 1
        
        # Create component
        comp = self.create_cyclonedx_component(comp_data)
        bom_obj.components.add(comp)
        
        # Create VEX vulnerability
        vuln = self.create_vex_vulnerability(vuln_id, status, justification, impact_statement)
        
        # Add vulnerability to BOM
        bom_obj.vulnerabilities.add(vuln)
        
        # Generate JSON output
        json_outputter = JsonV1Dot4(bom_obj)
        return json_outputter.output_as_string()
    
    def generate_vex_from_file(self, input_file: str, vuln_id: str, status: str, 
                             justification: Optional[str] = None, impact_statement: Optional[str] = None) -> str:
        """Generate VEX document from cve-bin-tool JSON file."""
        # Load and validate input data
        cve_bin_data = self.load_cve_bin_tool_data(input_file)
        
        # Generate VEX document
        return self.generate_vex_document(cve_bin_data, vuln_id, status, justification, impact_statement)
