"""
VEX Editor - Core logic for editing VEX documents in CycloneDX, CSAF, and OpenVEX formats.
"""

import json
import uuid
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum
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


class VEXFormat(Enum):
    """Supported VEX document formats."""
    CYCLONEDX = "cyclonedx"
    CSAF = "csaf"
    OPENVEX = "openvex"


class VEXEditor:
    """Edits VEX documents in CycloneDX, CSAF, and OpenVEX JSON formats."""
    
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
        """Initialize the VEX editor."""
        self.supported_formats = [VEXFormat.CYCLONEDX, VEXFormat.CSAF, VEXFormat.OPENVEX]
    
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
    
    def detect_vex_format(self, file_path: str) -> VEXFormat:
        """Detect the format of an existing VEX document."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check for CycloneDX format
            if isinstance(data, dict):
                if 'bomFormat' in data and data.get('bomFormat') == 'CycloneDX':
                    return VEXFormat.CYCLONEDX
                
                # Check for CSAF format
                if 'document' in data and 'csaf_version' in data.get('document', {}):
                    return VEXFormat.CSAF
                
                # Check for OpenVEX format
                if '@context' in data and 'openvex' in str(data.get('@context', '')).lower():
                    return VEXFormat.OPENVEX
                
                # Additional OpenVEX detection
                if 'author' in data and 'role' in data and 'timestamp' in data:
                    return VEXFormat.OPENVEX
            
            # Default to CycloneDX if format cannot be determined
            return VEXFormat.CYCLONEDX
            
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise ValueError(f"Error reading VEX file {file_path}: {e}")
    
    def load_existing_vex(self, file_path: str) -> Dict[str, Any]:
        """Load an existing VEX document for editing."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"VEX file not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                vex_data = json.load(f)
            
            # Detect and validate format
            vex_format = self.detect_vex_format(file_path)
            
            return {
                'data': vex_data,
                'format': vex_format,
                'path': file_path
            }
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in VEX file {file_path}: {e}")
    
    def edit_vex_vulnerability(self, vex_document: Dict[str, Any], vuln_id: str, 
                             status: str, justification: Optional[str] = None, 
                             impact_statement: Optional[str] = None) -> Dict[str, Any]:
        """Edit vulnerability information in an existing VEX document."""
        vex_data = vex_document['data']
        vex_format = vex_document['format']
        
        self.validate_status(status)
        if justification:
            self.validate_justification(justification)
        
        if vex_format == VEXFormat.CYCLONEDX:
            return self._edit_cyclonedx_vulnerability(vex_data, vuln_id, status, justification, impact_statement)
        elif vex_format == VEXFormat.CSAF:
            return self._edit_csaf_vulnerability(vex_data, vuln_id, status, justification, impact_statement)
        elif vex_format == VEXFormat.OPENVEX:
            return self._edit_openvex_vulnerability(vex_data, vuln_id, status, justification, impact_statement)
        else:
            raise ValueError(f"Unsupported VEX format: {vex_format}")
    
    def _edit_cyclonedx_vulnerability(self, vex_data: Dict[str, Any], vuln_id: str, 
                                    status: str, justification: Optional[str] = None, 
                                    impact_statement: Optional[str] = None) -> Dict[str, Any]:
        """Edit vulnerability in CycloneDX format VEX document."""
        # Find existing vulnerability
        vulnerabilities = vex_data.get('vulnerabilities', [])
        vuln_found = False
        
        for vuln in vulnerabilities:
            if vuln.get('id') == vuln_id:
                # Update existing vulnerability analysis
                if 'analysis' not in vuln:
                    vuln['analysis'] = {}
                
                vuln['analysis']['state'] = self._map_status_to_cyclonedx_state(status)
                
                if justification:
                    vuln['analysis']['justification'] = self._map_justification_to_cyclonedx_justification(justification)
                
                if impact_statement:
                    vuln['analysis']['detail'] = impact_statement
                
                vuln_found = True
                break
        
        if not vuln_found:
            # Add new vulnerability if not found
            new_vuln = {
                'id': vuln_id,
                'source': {
                    'name': 'NVD',
                    'url': f'https://nvd.nist.gov/vuln/detail/{vuln_id}'
                },
                'analysis': {
                    'state': self._map_status_to_cyclonedx_state(status)
                }
            }
            
            if justification:
                new_vuln['analysis']['justification'] = self._map_justification_to_cyclonedx_justification(justification)
            
            if impact_statement:
                new_vuln['analysis']['detail'] = impact_statement
            
            vulnerabilities.append(new_vuln)
            vex_data['vulnerabilities'] = vulnerabilities
        
        return vex_data
    
    def _edit_csaf_vulnerability(self, vex_data: Dict[str, Any], vuln_id: str, 
                               status: str, justification: Optional[str] = None, 
                               impact_statement: Optional[str] = None) -> Dict[str, Any]:
        """Edit vulnerability in CSAF format VEX document."""
        # TODO: Implement CSAF-specific editing logic
        # This is a placeholder for CSAF format support
        print(f"CSAF format editing not yet implemented. Would edit {vuln_id} with status {status}")
        return vex_data
    
    def _edit_openvex_vulnerability(self, vex_data: Dict[str, Any], vuln_id: str, 
                                  status: str, justification: Optional[str] = None, 
                                  impact_statement: Optional[str] = None) -> Dict[str, Any]:
        """Edit vulnerability in OpenVEX format VEX document."""
        # TODO: Implement OpenVEX-specific editing logic
        # This is a placeholder for OpenVEX format support
        print(f"OpenVEX format editing not yet implemented. Would edit {vuln_id} with status {status}")
        return vex_data
    
    def _map_status_to_cyclonedx_state(self, status: str) -> str:
        """Map VEX status to CycloneDX vulnerability analysis state string."""
        mapping = {
            VEXStatus.NOT_AFFECTED: "not_affected",
            VEXStatus.AFFECTED: "exploitable", 
            VEXStatus.FIXED: "resolved",
            VEXStatus.UNDER_INVESTIGATION: "in_triage"
        }
        return mapping.get(status, status)
    
    def _map_justification_to_cyclonedx_justification(self, justification: str) -> str:
        """Map VEX justification to CycloneDX vulnerability analysis justification string."""
        mapping = {
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT: "code_not_present",
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: "code_not_reachable", 
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: "requires_configuration",
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST: "requires_dependency"
        }
        return mapping.get(justification, justification)
    
    def save_vex_document(self, vex_data: Dict[str, Any], output_path: str) -> None:
        """Save the edited VEX document to a file."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(vex_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise ValueError(f"Error saving VEX document to {output_path}: {e}")
    
    def edit_existing_vex_file(self, input_file: str, vuln_id: str, status: str,
                             justification: Optional[str] = None, impact_statement: Optional[str] = None,
                             output_file: Optional[str] = None) -> str:
        """Edit an existing VEX file and return the updated content."""
        # Load existing VEX document
        vex_document = self.load_existing_vex(input_file)
        
        # Edit the vulnerability
        updated_data = self.edit_vex_vulnerability(vex_document, vuln_id, status, justification, impact_statement)
        
        # Determine output file
        if output_file is None:
            output_file = input_file  # Overwrite original file
        
        # Save the updated document
        self.save_vex_document(updated_data, output_file)
        
        # Return the JSON string
        return json.dumps(updated_data, indent=2, ensure_ascii=False)
