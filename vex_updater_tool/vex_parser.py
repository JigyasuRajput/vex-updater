"""
VEX Parser module - Enhanced VEX file parsing and manipulation using lib4vex.

This module provides a format-agnostic interface for loading, saving, and manipulating
VEX documents across CycloneDX, CSAF, and OpenVEX formats using the lib4vex library.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

# Import lib4vex components
from lib4vex.parser import VEXParser as Lib4VEXParser
from lib4vex.generator import VEXGenerator


class VEXFormat(Enum):
    """Supported VEX document formats."""
    CYCLONEDX = "cyclonedx"
    CSAF = "csaf"
    OPENVEX = "openvex"
    UNKNOWN = "unknown"


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


class VEXParser:
    """Enhanced VEX file parsing and manipulation using lib4vex."""
    
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
        """Initialize the VEX parser with lib4vex support."""
        self.lib4vex_parser = Lib4VEXParser(vex_type='auto')
        self.lib4vex_generator = VEXGenerator()
    
    def load_vex_document(self, file_path: str) -> Dict[str, Any]:
        """
        Load a VEX document from file using lib4vex.
        
        Args:
            file_path: Path to the VEX document file
            
        Returns:
            Dict containing the loaded VEX data and metadata
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"VEX file not found: {file_path}")
        
        try:
            # Use lib4vex to parse the document
            self.lib4vex_parser.parse(file_path)
            
            # Get format information
            vex_format_str = self.lib4vex_parser.get_type()
            vex_format = self._map_lib4vex_format_to_enum(vex_format_str)
            
            return {
                'data': self.lib4vex_parser.get_vulnerabilities(),
                'metadata': self.lib4vex_parser.get_metadata(),
                'product': self.lib4vex_parser.get_product(),
                'format': vex_format,
                'path': file_path,
                'raw_parser': self.lib4vex_parser
            }
            
        except Exception as e:
            raise ValueError(f"Error loading VEX document {file_path}: {e}")
    
    def save_vex_document(self, vex_data: Dict[str, Any], file_path: str) -> None:
        """
        Save VEX data to file using lib4vex.
        
        Args:
            vex_data: VEX data dictionary with vulnerabilities and metadata
            file_path: Path where to save the VEX document
        """
        try:
            # Determine format from vex_data or default to CycloneDX
            vex_format = vex_data.get('format', VEXFormat.CYCLONEDX)
            
            # For backward compatibility, check if this is raw VEX data instead of our structured format
            if 'data' not in vex_data and ('vulnerabilities' in vex_data or 'statements' in vex_data):
                # This is a raw VEX document, save it directly
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(vex_data, f, indent=2, ensure_ascii=False)
                return
            
            # Set up generator for the appropriate format
            format_str = self._map_format_enum_to_lib4vex(vex_format)
            generator = VEXGenerator(vex_type=format_str)
            
            # Set product information if available
            product_info = vex_data.get('product', {})
            if isinstance(product_info, dict) and product_info:
                generator.set_product(
                    name=product_info.get('name', ''),
                    release=product_info.get('version', ''),
                    sbom=product_info.get('sbom', '')
                )
            
            # Generate and save the document
            generator.generate(
                vex_data=vex_data.get('data', []),
                metadata=vex_data.get('metadata', {}),
                filename=file_path
            )
            
        except Exception as e:
            # Fallback to fallback save method
            try:
                self.save_vex_document_fallback(vex_data, file_path)
            except Exception as fallback_error:
                # Always propagate original permission errors as PermissionError/OSError
                if isinstance(e, (PermissionError, OSError)) or isinstance(fallback_error, (PermissionError, OSError)):
                    raise
                raise ValueError(f"Error saving VEX document to {file_path}: {e}. Fallback error: {fallback_error}")
    
    def get_vulnerabilities_from_vex(self, vex_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract vulnerability list from VEX data.
        
        Args:
            vex_data: VEX data dictionary
            
        Returns:
            List of vulnerability dictionaries
        """
        return vex_data.get('data', [])
    
    def add_vulnerability_to_vex(self, vex_data: Dict[str, Any], vuln_statement: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add a new vulnerability statement to VEX data.
        
        Args:
            vex_data: Existing VEX data dictionary
            vuln_statement: New vulnerability statement to add
            
        Returns:
            Updated VEX data dictionary
        """
        vulnerabilities = vex_data.get('data', [])
        
        # Check if vulnerability already exists
        vuln_id = vuln_statement.get('id')
        existing_vuln = None
        for i, vuln in enumerate(vulnerabilities):
            if vuln.get('id') == vuln_id:
                existing_vuln = i
                break
        
        if existing_vuln is not None:
            # Update existing vulnerability
            vulnerabilities[existing_vuln] = vuln_statement
        else:
            # Add new vulnerability
            vulnerabilities.append(vuln_statement)
        
        vex_data['data'] = vulnerabilities
        return vex_data
    
    def _map_lib4vex_format_to_enum(self, format_str: str) -> VEXFormat:
        """Map lib4vex format string to VEXFormat enum."""
        mapping = {
            'cyclonedx': VEXFormat.CYCLONEDX,
            'csaf': VEXFormat.CSAF,
            'openvex': VEXFormat.OPENVEX
        }
        return mapping.get(format_str.lower(), VEXFormat.CYCLONEDX)
    
    def _map_format_enum_to_lib4vex(self, vex_format: VEXFormat) -> str:
        """Map VEXFormat enum to lib4vex format string."""
        mapping = {
            VEXFormat.CYCLONEDX: 'cyclonedx',
            VEXFormat.CSAF: 'csaf',
            VEXFormat.OPENVEX: 'openvex'
        }
        return mapping.get(vex_format, 'cyclonedx')
    
    def detect_vex_format(self, file_path: str) -> VEXFormat:
        """Detect the format of an existing VEX document using lib4vex."""
        try:
            # Use lib4vex to detect format
            temp_parser = Lib4VEXParser(vex_type='auto')
            temp_parser.parse(file_path)
            format_str = temp_parser.get_type()
            return self._map_lib4vex_format_to_enum(format_str)
            
        except Exception as e:
            # Fallback to manual detection if lib4vex fails
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
                
            except (json.JSONDecodeError, FileNotFoundError) as fallback_error:
                # Surface a clear error so callers can validate inputs accordingly
                print("[ERROR] Unable to determine type of VEX document")
                raise ValueError(f"Error reading VEX file {file_path}: {fallback_error}")
    
    def load_existing_vex(self, file_path: str) -> Dict[str, Any]:
        """Load an existing VEX document for processing using lib4vex."""
        # Use the new load_vex_document method for backward compatibility
        return self.load_vex_document(file_path)
    
    def extract_vulnerabilities_from_vex(self, vex_document: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerability information from a VEX document using lib4vex."""
        # Use the new get_vulnerabilities_from_vex method for consistency
        return self.get_vulnerabilities_from_vex(vex_document)
    
    # Legacy mapping methods for backward compatibility
    def _map_cyclonedx_state_to_status(self, state: str) -> str:
        """Map CycloneDX vulnerability analysis state to VEX status."""
        mapping = {
            "not_affected": VEXStatus.NOT_AFFECTED,
            "exploitable": VEXStatus.AFFECTED,
            "resolved": VEXStatus.FIXED,
            "in_triage": VEXStatus.UNDER_INVESTIGATION
        }
        return mapping.get(state, state)
    
    def _map_cyclonedx_justification_to_vex(self, justification: str) -> str:
        """Map CycloneDX justification to VEX justification."""
        mapping = {
            "code_not_present": VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            "code_not_reachable": VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            "requires_configuration": VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
            "requires_dependency": VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST
        }
        return mapping.get(justification, justification)
    
    def update_vex_vulnerability(self, vex_document: Dict[str, Any], vuln_id: str, 
                               status: str, justification: Optional[str] = None, 
                               impact_statement: Optional[str] = None) -> Dict[str, Any]:
        """Update vulnerability information in a VEX document using lib4vex."""
        # Validate inputs
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(self.VALID_STATUSES)}")
        
        if justification and justification not in self.VALID_JUSTIFICATIONS:
            raise ValueError(f"Invalid justification '{justification}'. Must be one of: {', '.join(self.VALID_JUSTIFICATIONS)}")
        
        # Check if this is our structured format or raw VEX data
        if 'data' in vex_document and isinstance(vex_document['data'], list):
            # This is our structured format with lib4vex data
            vulnerabilities = vex_document['data']
            
            # Find and update existing vulnerability or add new one
            vuln_found = False
            for vuln in vulnerabilities:
                if vuln.get('id') == vuln_id:
                    # Update existing vulnerability
                    vuln['status'] = status
                    if justification:
                        vuln['justification'] = justification
                    if impact_statement:
                        vuln['comment'] = impact_statement
                    vuln_found = True
                    break
            
            if not vuln_found:
                # Add new vulnerability
                new_vuln = {
                    'id': vuln_id,
                    'status': status,
                    'source-name': 'NVD',
                    'source-url': f'https://nvd.nist.gov/vuln/detail/{vuln_id}'
                }
                if justification:
                    new_vuln['justification'] = justification
                if impact_statement:
                    new_vuln['comment'] = impact_statement
                vulnerabilities.append(new_vuln)
            
            return vex_document
            
        else:
            # This is raw VEX document data, handle using fallback approach
            # Check if it's CycloneDX format
            if 'vulnerabilities' in vex_document:
                return self._update_cyclonedx_vulnerability_raw(vex_document, vuln_id, status, justification, impact_statement)
            else:
                # For other formats, add basic support
                vex_document.setdefault('vulnerabilities', [])
                return self._update_cyclonedx_vulnerability_raw(vex_document, vuln_id, status, justification, impact_statement)
    
    def _update_cyclonedx_vulnerability_raw(self, vex_data: Dict[str, Any], vuln_id: str, 
                                          status: str, justification: Optional[str] = None, 
                                          impact_statement: Optional[str] = None) -> Dict[str, Any]:
        """Update vulnerability in raw CycloneDX format VEX document."""
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
    
    def save_vex_document_fallback(self, vex_data: Dict[str, Any], output_path: str) -> None:
        """Save the updated VEX document to a file (fallback method for backward compatibility)."""
        try:
            # Create a copy of vex_data to avoid modifying the original
            data_to_save = vex_data.copy()
            
            # Remove or convert non-JSON serializable objects
            if 'format' in data_to_save and hasattr(data_to_save['format'], 'value'):
                data_to_save['format'] = data_to_save['format'].value
            
            # Remove non-serializable objects
            non_serializable_keys = ['raw_parser']
            for key in non_serializable_keys:
                data_to_save.pop(key, None)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise ValueError(f"Error saving VEX document to {output_path}: {e}")
    
    # Alias methods for backward compatibility
    def detect_format(self, file_path_or_data: str) -> VEXFormat:
        """Alias for detect_vex_format method."""
        if isinstance(file_path_or_data, str) and os.path.exists(file_path_or_data):
            return self.detect_vex_format(file_path_or_data)
        else:
            # If it's data, try to detect from structure
            try:
                data = json.loads(file_path_or_data) if isinstance(file_path_or_data, str) else file_path_or_data
                if 'bomFormat' in data and data.get('bomFormat') == 'CycloneDX':
                    return VEXFormat.CYCLONEDX
                elif 'document' in data and 'category' in data['document']:
                    return VEXFormat.CSAF
                else:
                    return VEXFormat.CYCLONEDX  # Default fallback
            except:
                return VEXFormat.CYCLONEDX  # Default fallback
    
    def load_vex_file(self, file_path: str):
        """Load VEX file and return data with format."""
        format_type = self.detect_vex_format(file_path)
        data = self.load_vex_document(file_path)
        return data, format_type
    
    def save_vex_file(self, vex_data: Dict[str, Any], file_path: str, format_type: VEXFormat) -> None:
        """Save VEX file in specified format."""
        self.save_vex_document(vex_data, file_path)
    
    def extract_vulnerabilities(self, vex_data: Dict[str, Any], format_type: VEXFormat) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from VEX data."""
        return self.extract_vulnerabilities_from_vex(vex_data)
    
    def add_vulnerability(self, vex_data: Dict[str, Any], vulnerability: Dict[str, Any], format_type: VEXFormat) -> Dict[str, Any]:
        """Add vulnerability to VEX data."""
        return self.add_vulnerability_to_vex(vex_data, vulnerability)
    
    def update_vulnerability(self, vex_data: Dict[str, Any], vuln_id: str, updates: Dict[str, Any], format_type: VEXFormat = None) -> Dict[str, Any]:
        """Update existing vulnerability in VEX data."""
        return self.update_vex_vulnerability(vex_data, vuln_id, **updates)
    
    def remove_vulnerability(self, vex_data: Dict[str, Any], vuln_id: str, format_type: VEXFormat = None) -> Dict[str, Any]:
        """Remove vulnerability from VEX data."""
        # For now, implement a basic removal
        updated_data = vex_data.copy()
        if 'vulnerabilities' in updated_data:
            updated_data['vulnerabilities'] = [
                v for v in updated_data['vulnerabilities'] 
                if v.get('id') != vuln_id
            ]
        return updated_data
    
    def convert_format(self, vex_data: Dict[str, Any], source_format: VEXFormat, target_format: VEXFormat) -> Dict[str, Any]:
        """Convert VEX data from one format to another."""
        # For now, return the same data (basic implementation)
        # In a full implementation, this would handle format conversion
        return vex_data.copy()
    
    def map_status_to_format(self, status: str, format_type: VEXFormat) -> str:
        """Map generic status to format-specific status."""
        if format_type == VEXFormat.CYCLONEDX:
            return self._map_status_to_cyclonedx_state(status)
        elif format_type == VEXFormat.CSAF:
            # Map to CSAF status
            status_map = {
                VEXStatus.NOT_AFFECTED: 'not_affected',
                VEXStatus.AFFECTED: 'affected',
                VEXStatus.FIXED: 'fixed',
                VEXStatus.UNDER_INVESTIGATION: 'under_investigation'
            }
            return status_map.get(status, status)
        return status
    
    def map_justification_to_format(self, justification: str, format_type: VEXFormat) -> str:
        """Map generic justification to format-specific justification."""
        if format_type == VEXFormat.CYCLONEDX:
            return self._map_justification_to_cyclonedx_justification(justification)
        elif format_type == VEXFormat.CSAF:
            # Map to CSAF justification
            justification_map = {
                VEXJustification.VULNERABLE_CODE_NOT_PRESENT: 'vulnerable_code_not_present',
                VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: 'vulnerable_code_not_in_execute_path',
                VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: 'vulnerable_code_cannot_be_controlled_by_adversary',
                VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST: 'inline_mitigations_already_exist'
            }
            return justification_map.get(justification, justification)
        return justification
    
    def validate_vex_structure(self, vex_data: Dict[str, Any], format_type: VEXFormat) -> bool:
        """Validate VEX structure for the given format."""
        try:
            if format_type == VEXFormat.CYCLONEDX:
                # Must contain mandatory fields and correct types
                if not ('bomFormat' in vex_data and vex_data.get('bomFormat') == 'CycloneDX'):
                    return False
                if 'vulnerabilities' in vex_data and not isinstance(vex_data['vulnerabilities'], list):
                    return False
                return True
            elif format_type == VEXFormat.CSAF:
                return 'document' in vex_data and 'category' in vex_data.get('document', {})
            return False
        except:
            return False
    
    def validate_schema(self, vex_data: Dict[str, Any], format_type: VEXFormat) -> Dict[str, Any]:
        """Validate VEX data against schema."""
        try:
            is_valid = self.validate_vex_structure(vex_data, format_type)
            errors: List[str] = []
            if not is_valid:
                errors.append('Invalid structure for format')
            # Additional light-weight checks for CycloneDX
            if format_type == VEXFormat.CYCLONEDX:
                if not isinstance(vex_data.get('version', 0), int):
                    errors.append('version must be integer')
                metadata = vex_data.get('metadata', {})
                if metadata and not isinstance(metadata.get('tools', []), list):
                    errors.append('metadata.tools must be array')
                if 'serialNumber' in vex_data and not str(vex_data['serialNumber']).startswith('urn:uuid:'):
                    errors.append('serialNumber must be a URN UUID')
            return {
                'is_valid': len(errors) == 0,
                'errors': errors
            }
        except Exception as e:
            return {
                'is_valid': False,
                'errors': [str(e)]
            }