"""
Scan Parser module - Handles parsing of cve-bin-tool output and other vulnerability scan formats.
"""

import json
from typing import Dict, List, Any, Optional


class ScanParser:
    """Parses vulnerability scan outputs from various tools."""
    
    def __init__(self):
        """Initialize the scan parser."""
        pass
    
    def load_cve_bin_tool_data(self, file_path: str) -> Dict[str, Any]:
        """Load and parse cve-bin-tool JSON output."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Validate basic structure
            if not isinstance(data, dict):
                raise ValueError("Input JSON must be a dictionary")
            
            # Handle both formats: components-based and vulnerabilities-based
            if 'components' in data:
                # Standard components format
                if not isinstance(data['components'], list):
                    raise ValueError("'components' field must be a list")
                return data
            elif 'vulnerabilities' in data:
                # Convert vulnerabilities format to components format
                return self._convert_vulnerabilities_to_components_format(data)
            else:
                raise ValueError("Input JSON must contain either 'components' or 'vulnerabilities' field")
        
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {file_path}")
        except Exception as e:
            raise ValueError(f"Error reading input file: {e}")
    
    def _convert_vulnerabilities_to_components_format(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert vulnerabilities-based format to components-based format."""
        components_map = {}
        
        for vuln in data.get('vulnerabilities', []):
            if 'component' not in vuln:
                continue
                
            component_info = vuln['component']
            component_key = f"{component_info.get('name', 'unknown')}:{component_info.get('version', '0.0.0')}"
            
            if component_key not in components_map:
                components_map[component_key] = {
                    'name': component_info.get('name', 'unknown'),
                    'version': component_info.get('version', '0.0.0'),
                    'purl': component_info.get('purl'),
                    'vulnerabilities': []
                }
            
            vuln_entry = {
                'vuln_id': vuln.get('cve_id'),
                'description': vuln.get('description', ''),
                'severity': vuln.get('severity'),
                'cvss_score': vuln.get('cvss_score')
            }
            components_map[component_key]['vulnerabilities'].append(vuln_entry)
        
        # Convert to components format
        converted_data = data.copy()
        converted_data['components'] = list(components_map.values())
        
        return converted_data
    
    def find_component_with_vulnerability(self, scan_data: Dict[str, Any], vuln_id: str) -> Optional[Dict[str, Any]]:
        """Find the component that contains the specified vulnerability."""
        for comp in scan_data.get('components', []):
            if 'vulnerabilities' in comp:
                for vuln in comp['vulnerabilities']:
                    if vuln.get('vuln_id') == vuln_id:
                        return comp
        return None
    
    def extract_vulnerabilities_from_scan(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all vulnerabilities from scan data with associated component information."""
        vulnerabilities = []
        
        for comp in scan_data.get('components', []):
            if 'vulnerabilities' in comp:
                for vuln in comp['vulnerabilities']:
                    vuln_entry = {
                        'vuln_id': vuln.get('vuln_id'),
                        'description': vuln.get('description', ''),
                        'component': {
                            'name': comp.get('name', 'unknown'),
                            'version': comp.get('version', '0.0.0'),
                            'purl': comp.get('purl')
                        }
                    }
                    vulnerabilities.append(vuln_entry)
        
        return vulnerabilities
    
    def validate_scan_format(self, scan_data: Dict[str, Any]) -> bool:
        """Validate that the scan data follows expected format."""
        try:
            if not isinstance(scan_data, dict):
                return False
            
            # Handle components format
            if 'components' in scan_data:
                components = scan_data['components']
                if not isinstance(components, list):
                    return False
                
                # Check that at least one component has the expected structure
                for comp in components:
                    if not isinstance(comp, dict):
                        return False
                    
                    # Check for required component fields
                    if 'name' in comp and 'vulnerabilities' in comp:
                        vulns = comp['vulnerabilities']
                        if isinstance(vulns, list):
                            for vuln in vulns:
                                if isinstance(vuln, dict) and 'vuln_id' in vuln:
                                    return True
                
                return True  # Empty or minimal valid structure
            
            # Handle vulnerabilities format
            elif 'vulnerabilities' in scan_data:
                vulnerabilities = scan_data['vulnerabilities']
                if not isinstance(vulnerabilities, list):
                    return False
                
                # Check that at least one vulnerability has the expected structure
                for vuln in vulnerabilities:
                    if not isinstance(vuln, dict):
                        return False
                    
                    # Check for required fields
                    if 'cve_id' in vuln and 'component' in vuln:
                        component = vuln['component']
                        if isinstance(component, dict) and 'name' in component:
                            return True
                
                return True  # Empty or minimal valid structure
            
            return False  # No recognized format
            
        except Exception:
            return False
