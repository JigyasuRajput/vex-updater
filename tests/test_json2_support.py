"""
Test the JSON2 format support functionality.
"""

import pytest
import json
import tempfile
import os
from vex_updater_tool.scan_parser import ScanParser


class TestJSON2Support:
    """Test the JSON2 format support functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = ScanParser()
    
    def test_detect_json2_format_with_metadata(self):
        """Test detection of JSON2 format with metadata."""
        json2_data = {
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z"
            },
            "results": [
                {
                    "cve_id": "CVE-2021-44228",
                    "package": {
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                    },
                    "description": "Remote code execution in log4j.",
                    "severity": "HIGH",
                    "cvss_score": 9.8
                }
            ]
        }
        
        format_type = self.parser._detect_format(json2_data)
        assert format_type == 'json2'
    
    def test_detect_json2_format_with_results(self):
        """Test detection of JSON2 format with results array."""
        json2_data = {
            "results": [
                {
                    "cve_id": "CVE-2021-44228",
                    "package": {
                        "name": "log4j-core",
                        "version": "2.14.1"
                    }
                }
            ]
        }
        
        format_type = self.parser._detect_format(json2_data)
        assert format_type == 'json2'
    
    def test_detect_components_format(self):
        """Test detection of standard components format."""
        components_data = {
            "components": [
                {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "vulnerabilities": [
                        {
                            "vuln_id": "CVE-2021-44228",
                            "description": "Remote code execution in log4j."
                        }
                    ]
                }
            ]
        }
        
        format_type = self.parser._detect_format(components_data)
        assert format_type == 'components'
    
    def test_detect_vulnerabilities_format(self):
        """Test detection of vulnerabilities format."""
        vulnerabilities_data = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2021-44228",
                    "component": {
                        "name": "log4j-core",
                        "version": "2.14.1"
                    }
                }
            ]
        }
        
        format_type = self.parser._detect_format(vulnerabilities_data)
        assert format_type == 'vulnerabilities'
    
    def test_convert_json2_to_components_format(self):
        """Test conversion of JSON2 format to components format."""
        json2_data = {
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z"
            },
            "results": [
                {
                    "cve_id": "CVE-2021-44228",
                    "package": {
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                    },
                    "description": "Remote code execution in log4j.",
                    "severity": "HIGH",
                    "cvss_score": 9.8
                },
                {
                    "cve_id": "CVE-2021-45046",
                    "package": {
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                    },
                    "description": "Another log4j vulnerability.",
                    "severity": "MEDIUM",
                    "cvss_score": 6.5
                }
            ]
        }
        
        converted_data = self.parser._convert_json2_to_components_format(json2_data)
        
        # Check that components array exists
        assert 'components' in converted_data
        assert len(converted_data['components']) == 1
        
        # Check component structure
        component = converted_data['components'][0]
        assert component['name'] == 'log4j-core'
        assert component['version'] == '2.14.1'
        assert component['purl'] == 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'
        
        # Check vulnerabilities
        assert len(component['vulnerabilities']) == 2
        vuln_ids = [v['vuln_id'] for v in component['vulnerabilities']]
        assert 'CVE-2021-44228' in vuln_ids
        assert 'CVE-2021-45046' in vuln_ids
    
    def test_convert_json2_with_multiple_components(self):
        """Test conversion of JSON2 format with multiple components."""
        json2_data = {
            "results": [
                {
                    "cve_id": "CVE-2021-44228",
                    "package": {
                        "name": "log4j-core",
                        "version": "2.14.1"
                    },
                    "description": "Remote code execution in log4j."
                },
                {
                    "cve_id": "CVE-2021-45046",
                    "package": {
                        "name": "log4j-api",
                        "version": "2.14.1"
                    },
                    "description": "Another log4j vulnerability."
                }
            ]
        }
        
        converted_data = self.parser._convert_json2_to_components_format(json2_data)
        
        # Check that we have two components
        assert len(converted_data['components']) == 2
        
        # Check component names
        component_names = [c['name'] for c in converted_data['components']]
        assert 'log4j-core' in component_names
        assert 'log4j-api' in component_names
    
    def test_load_json2_data_from_file(self):
        """Test loading JSON2 data from a file."""
        json2_data = {
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z"
            },
            "results": [
                {
                    "cve_id": "CVE-2021-44228",
                    "package": {
                        "name": "log4j-core",
                        "version": "2.14.1"
                    },
                    "description": "Remote code execution in log4j."
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(json2_data, f)
            temp_file = f.name
        
        try:
            loaded_data = self.parser.load_cve_bin_tool_data(temp_file)
            
            # Check that the data was converted to components format
            assert 'components' in loaded_data
            assert len(loaded_data['components']) == 1
            
            component = loaded_data['components'][0]
            assert component['name'] == 'log4j-core'
            assert len(component['vulnerabilities']) == 1
            assert component['vulnerabilities'][0]['vuln_id'] == 'CVE-2021-44228'
        
        finally:
            os.unlink(temp_file)
    
    def test_validate_json2_format(self):
        """Test validation of JSON2 format."""
        json2_data = {
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z"
            },
            "results": [
                {
                    "cve_id": "CVE-2021-44228",
                    "package": {
                        "name": "log4j-core",
                        "version": "2.14.1"
                    },
                    "description": "Remote code execution in log4j."
                }
            ]
        }
        
        is_valid = self.parser.validate_scan_format(json2_data)
        assert is_valid is True
    
    def test_validate_invalid_json2_format(self):
        """Test validation of invalid JSON2 format."""
        invalid_data = {
            "results": [
                {
                    "package": {
                        "name": "log4j-core"
                    }
                    # Missing cve_id
                }
            ]
        }
        
        is_valid = self.parser.validate_scan_format(invalid_data)
        assert is_valid is False
    
    def test_json2_fallback_to_vulnerabilities(self):
        """Test that JSON2 format falls back to vulnerabilities format when needed."""
        json2_data = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2021-44228",
                    "component": {
                        "name": "log4j-core",
                        "version": "2.14.1"
                    }
                }
            ]
        }
        
        converted_data = self.parser._convert_json2_to_components_format(json2_data)
        
        # Should have been converted to components format
        assert 'components' in converted_data
        assert len(converted_data['components']) == 1
        assert converted_data['components'][0]['name'] == 'log4j-core'
