"""
Scan Parser module - Handles parsing of cve-bin-tool output and other vulnerability scan formats.
"""

import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class ScanParser:
    """Parses vulnerability scan outputs from various tools."""
    
    def __init__(self):
        """Initialize the scan parser."""
        pass
    
    def load_cve_bin_tool_data(self, file_path: str) -> Dict[str, Any]:
        """Load and parse cve-bin-tool JSON output (supports both JSON and JSON2 formats)."""
        logger.debug(f"Loading cve-bin-tool data from: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            logger.debug(f"Successfully loaded JSON data with keys: {list(data.keys())}")
            
            # Validate basic structure
            if not isinstance(data, dict):
                raise ValueError("Input JSON must be a dictionary")
            
            # Detect and handle different cve-bin-tool output formats
            format_type = self._detect_format(data)
            logger.info(f"Detected format: {format_type}")
            
            if format_type == 'components':
                # Standard components format (JSON)
                logger.info("Processing components-based format (JSON)")
                if not isinstance(data['components'], list):
                    raise ValueError("'components' field must be a list")
                logger.debug(f"Found {len(data['components'])} components")
                return data
            elif format_type == 'vulnerabilities':
                # Vulnerabilities format (JSON2)
                logger.info("Processing vulnerabilities-based format (JSON2), converting to components format")
                converted_data = self._convert_vulnerabilities_to_components_format(data)
                logger.debug(f"Converted to components format with {len(converted_data.get('components', []))} components")
                return converted_data
            elif format_type == 'json2':
                # JSON2 format with different structure
                logger.info("Processing JSON2 format, converting to components format")
                converted_data = self._convert_json2_to_components_format(data)
                logger.debug(f"Converted JSON2 to components format with {len(converted_data.get('components', []))} components")
                return converted_data
            else:
                raise ValueError("Input JSON format not recognized. Expected cve-bin-tool JSON or JSON2 output. Must contain either 'components' or 'vulnerabilities' field.")
        
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            raise ValueError(f"Invalid JSON format: {e}")
        except FileNotFoundError:
            logger.error(f"Input file not found: {file_path}")
            raise FileNotFoundError(f"Input file not found: {file_path}")
        except ValueError as e:
            # Re-raise ValueError directly without wrapping
            raise e
        except Exception as e:
            logger.error(f"Unexpected error reading file: {e}")
            raise ValueError(f"Error reading input file: {e}")
    
    def _convert_vulnerabilities_to_components_format(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert vulnerabilities-based format to components-based format."""
        logger.debug("Converting vulnerabilities format to components format")
        components_map = {}
        
        vulnerabilities = data.get('vulnerabilities', [])
        logger.debug(f"Processing {len(vulnerabilities)} vulnerabilities")
        
        for vuln in vulnerabilities:
            if 'component' not in vuln:
                logger.warning(f"Vulnerability missing component info: {vuln.get('cve_id', 'unknown')}")
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
                logger.debug(f"Created new component entry: {component_key}")
            
            vuln_entry = {
                'vuln_id': vuln.get('cve_id'),
                'description': vuln.get('description', ''),
                'severity': vuln.get('severity'),
                'cvss_score': vuln.get('cvss_score')
            }
            components_map[component_key]['vulnerabilities'].append(vuln_entry)
            logger.debug(f"Added vulnerability {vuln.get('cve_id')} to component {component_key}")
        
        # Convert to components format
        converted_data = data.copy()
        converted_data['components'] = list(components_map.values())
        
        logger.info(f"Conversion complete: {len(components_map)} components created")
        return converted_data
    
    def _detect_format(self, data: Dict[str, Any]) -> str:
        """Detect the format of cve-bin-tool output."""
        logger.debug("Detecting cve-bin-tool output format")
        
        # Check for JSON2 format (newer cve-bin-tool versions)
        if 'metadata' in data and 'timestamp' in data.get('metadata', {}):
            logger.debug("Detected JSON2 format indicators")
            return 'json2'
        
        # Check for components format (standard JSON)
        if 'components' in data:
            if isinstance(data['components'], list):
                logger.debug("Detected components format (JSON)")
                return 'components'
            else:
                logger.debug("Found components field but it's not a list")
                return 'components'  # Still return components to trigger the validation error
        
        # Check for vulnerabilities format (older JSON2)
        if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
            logger.debug("Detected vulnerabilities format")
            return 'vulnerabilities'
        
        # Check for flat structure (alternative JSON2 format)
        if 'results' in data and isinstance(data['results'], list):
            logger.debug("Detected flat results format")
            return 'json2'
        
        logger.warning("Could not determine format")
        return 'unknown'
    
    def _convert_json2_to_components_format(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert JSON2 format to components format."""
        logger.debug("Converting JSON2 format to components format")
        components_map = {}
        
        # Handle different JSON2 structures
        if 'results' in data:
            # Flat results structure
            results = data.get('results', [])
            logger.debug(f"Processing {len(results)} results from JSON2 format")
            
            for result in results:
                if not isinstance(result, dict):
                    continue
                
                # Extract component info
                component_name = result.get('package', {}).get('name', 'unknown')
                component_version = result.get('package', {}).get('version', '0.0.0')
                component_purl = result.get('package', {}).get('purl')
                
                component_key = f"{component_name}:{component_version}"
                
                if component_key not in components_map:
                    components_map[component_key] = {
                        'name': component_name,
                        'version': component_version,
                        'purl': component_purl,
                        'vulnerabilities': []
                    }
                    logger.debug(f"Created new component entry: {component_key}")
                
                # Extract vulnerability info
                vuln_entry = {
                    'vuln_id': result.get('cve_id'),
                    'description': result.get('description', ''),
                    'severity': result.get('severity'),
                    'cvss_score': result.get('cvss_score')
                }
                components_map[component_key]['vulnerabilities'].append(vuln_entry)
                logger.debug(f"Added vulnerability {result.get('cve_id')} to component {component_key}")
        
        elif 'vulnerabilities' in data:
            # Standard vulnerabilities structure
            return self._convert_vulnerabilities_to_components_format(data)
        
        # Convert to components format
        converted_data = data.copy()
        converted_data['components'] = list(components_map.values())
        
        logger.info(f"JSON2 conversion complete: {len(components_map)} components created")
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
            
            # Detect format and validate accordingly
            format_type = self._detect_format(scan_data)
            logger.debug(f"Validating scan format: {format_type}")
            
            if format_type == 'components':
                # Handle components format
                components = scan_data.get('components', [])
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
            
            elif format_type == 'vulnerabilities':
                # Handle vulnerabilities format
                vulnerabilities = scan_data.get('vulnerabilities', [])
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
            
            elif format_type == 'json2':
                # Handle JSON2 format
                if 'results' in scan_data:
                    results = scan_data.get('results', [])
                    if not isinstance(results, list):
                        return False
                    
                    # Check that at least one result has the expected structure
                    for result in results:
                        if not isinstance(result, dict):
                            return False
                        
                        # Check for required fields in JSON2 format
                        if 'cve_id' in result and 'package' in result:
                            package = result['package']
                            if isinstance(package, dict) and 'name' in package:
                                return True
                    
                    # If we get here, no valid result was found
                    return False
                
                elif 'vulnerabilities' in scan_data:
                    # Fall back to vulnerabilities validation
                    return self.validate_scan_format({'vulnerabilities': scan_data['vulnerabilities']})
                
                return False  # No recognized structure
            
            elif format_type == 'unknown':
                # Unknown format - not valid
                return False
            
            return False  # No recognized format
            
        except Exception as e:
            logger.error(f"Error validating scan format: {e}")
            return False
