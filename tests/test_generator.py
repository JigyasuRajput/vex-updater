"""
Tests for the VEX generator module.
"""

import json
import tempfile
import os
import pytest
from unittest.mock import patch, mock_open

from vex_updater_tool.generator import VEXEditor
from vex_updater_tool.vex_parser import VEXStatus, VEXJustification, VEXFormat


class TestVEXEditor:
    """Test cases for VEXEditor class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.editor = VEXEditor()
        self.sample_cve_data = {
            "components": [
                {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    "vulnerabilities": [
                        {
                            "vuln_id": "CVE-2021-44228",
                            "description": "Remote code execution in log4j."
                        }
                    ]
                }
            ]
        }
        
        self.sample_cve_data_multiple = {
            "components": [
                {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    "vulnerabilities": [
                        {
                            "vuln_id": "CVE-2021-44228",
                            "description": "Remote code execution in log4j."
                        }
                    ]
                },
                {
                    "name": "jackson-databind",
                    "version": "2.12.0",
                    "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.0",
                    "vulnerabilities": [
                        {
                            "vuln_id": "CVE-2020-36518",
                            "description": "Java deserialization vulnerability."
                        }
                    ]
                }
            ]
        }
    
    def test_validate_status_valid(self):
        """Test status validation with valid values."""
        for status in VEXEditor.VALID_STATUSES:
            self.editor.validate_status(status)  # Should not raise
    
    def test_validate_status_invalid(self):
        """Test status validation with invalid values."""
        with pytest.raises(ValueError, match="Invalid status"):
            self.editor.validate_status("invalid_status")
    
    def test_validate_justification_valid(self):
        """Test justification validation with valid values."""
        for justification in VEXEditor.VALID_JUSTIFICATIONS:
            self.editor.validate_justification(justification)  # Should not raise
    
    def test_validate_justification_invalid(self):
        """Test justification validation with invalid values."""
        with pytest.raises(ValueError, match="Invalid justification"):
            self.editor.validate_justification("invalid_justification")
    
    def test_load_cve_bin_tool_data_valid_file(self):
        """Test loading valid cve-bin-tool JSON data."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_cve_data, f)
            temp_file = f.name
        
        try:
            data = self.editor.load_cve_bin_tool_data(temp_file)
            assert data == self.sample_cve_data
        finally:
            os.unlink(temp_file)
    
    def test_load_cve_bin_tool_data_file_not_found(self):
        """Test loading from non-existent file."""
        with pytest.raises(FileNotFoundError):
            self.editor.load_cve_bin_tool_data("non_existent_file.json")
    
    def test_load_cve_bin_tool_data_invalid_json(self):
        """Test loading invalid JSON data."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write("invalid json content")
            temp_file = f.name
        
        try:
            with pytest.raises(ValueError, match="Invalid JSON format"):
                self.editor.load_cve_bin_tool_data(temp_file)
        finally:
            os.unlink(temp_file)
    
    def test_load_cve_bin_tool_data_missing_components(self):
        """Test loading JSON without components field."""
        invalid_data = {"some_field": "some_value"}
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(invalid_data, f)
            temp_file = f.name
        
        try:
            with pytest.raises(ValueError, match="Input JSON format not recognized"):
                self.editor.load_cve_bin_tool_data(temp_file)
        finally:
            os.unlink(temp_file)
    
    def test_load_cve_bin_tool_data_invalid_components_type(self):
        """Test loading JSON with non-list components field."""
        invalid_data = {"components": "not_a_list"}
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(invalid_data, f)
            temp_file = f.name
        
        try:
            with pytest.raises(ValueError, match="'components' field must be a list"):
                self.editor.load_cve_bin_tool_data(temp_file)
        finally:
            os.unlink(temp_file)
    
    def test_find_component_with_vulnerability_found(self):
        """Test finding a component with a specific vulnerability."""
        component = self.editor.find_component_with_vulnerability(
            self.sample_cve_data, "CVE-2021-44228"
        )
        assert component is not None
        assert component["name"] == "log4j-core"
        assert component["version"] == "2.14.1"
    
    def test_find_component_with_vulnerability_not_found(self):
        """Test finding a component with a non-existent vulnerability."""
        component = self.editor.find_component_with_vulnerability(
            self.sample_cve_data, "CVE-9999-99999"
        )
        assert component is None
    
    def test_find_component_with_vulnerability_multiple_components(self):
        """Test finding the correct component among multiple components."""
        component = self.editor.find_component_with_vulnerability(
            self.sample_cve_data_multiple, "CVE-2020-36518"
        )
        assert component is not None
        assert component["name"] == "jackson-databind"
        assert component["version"] == "2.12.0"
    
    def test_create_cyclonedx_component_basic(self):
        """Test creating a basic CycloneDX component."""
        comp_data = {
            "name": "test-component",
            "version": "1.0.0"
        }
        
        component = self.editor.create_cyclonedx_component(comp_data)
        assert component.name == "test-component"
        assert component.version == "1.0.0"
    
    def test_create_cyclonedx_component_with_purl(self):
        """Test creating a CycloneDX component with PURL."""
        comp_data = {
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        }
        
        component = self.editor.create_cyclonedx_component(comp_data)
        assert component.name == "log4j-core"
        assert component.version == "2.14.1"
        # Note: PURL testing might require additional setup
    
    def test_create_cyclonedx_component_missing_fields(self):
        """Test creating a component with missing fields."""
        comp_data = {}
        
        component = self.editor.create_cyclonedx_component(comp_data)
        assert component.name == "unknown"
        assert component.version == "0.0.0"
    
    def test_create_vex_vulnerability_not_affected(self):
        """Test creating VEX vulnerability with not_affected status."""
        vuln = self.editor.create_vex_vulnerability(
            vuln_id="CVE-2021-44228",
            status=VEXStatus.NOT_AFFECTED,
            justification=VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            impact_statement="The vulnerable function is never called."
        )
        
        assert vuln.id == "CVE-2021-44228"
        assert vuln.analysis is not None
        assert vuln.analysis.detail == "The vulnerable function is never called."
    
    def test_create_vex_vulnerability_affected(self):
        """Test creating VEX vulnerability with affected status."""
        vuln = self.editor.create_vex_vulnerability(
            vuln_id="CVE-2021-44228",
            status=VEXStatus.AFFECTED,
            impact_statement="This affects our product."
        )
        
        assert vuln.id == "CVE-2021-44228"
        assert vuln.analysis is not None
        assert vuln.analysis.detail == "This affects our product."
    
    def test_create_vex_vulnerability_invalid_status(self):
        """Test creating VEX vulnerability with invalid status."""
        with pytest.raises(ValueError, match="Invalid status"):
            self.editor.create_vex_vulnerability(
                vuln_id="CVE-2021-44228",
                status="invalid_status"
            )
    
    def test_create_vex_vulnerability_invalid_justification(self):
        """Test creating VEX vulnerability with invalid justification."""
        with pytest.raises(ValueError, match="Invalid justification"):
            self.editor.create_vex_vulnerability(
                vuln_id="CVE-2021-44228",
                status=VEXStatus.NOT_AFFECTED,
                justification="invalid_justification"
            )
    
    def test_generate_vex_document_not_affected(self):
        """Test generating complete VEX document for not_affected status."""
        vex_json = self.editor.generate_vex_document(
            cve_bin_data=self.sample_cve_data,
            vuln_id="CVE-2021-44228",
            status=VEXStatus.NOT_AFFECTED,
            justification=VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            impact_statement="The vulnerable function is never called."
        )
        
        # Parse and validate the JSON structure
        vex_data = json.loads(vex_json)
        assert "bomFormat" in vex_data
        assert vex_data["bomFormat"] == "CycloneDX"
        assert "components" in vex_data
        assert "vulnerabilities" in vex_data
        assert len(vex_data["components"]) == 1
        assert len(vex_data["vulnerabilities"]) == 1
        
        # Check component
        component = vex_data["components"][0]
        assert component["name"] == "log4j-core"
        assert component["version"] == "2.14.1"
        
        # Check vulnerability
        vuln = vex_data["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2021-44228"
        assert "analysis" in vuln
    
    def test_generate_vex_document_vulnerability_not_found(self):
        """Test generating VEX document for non-existent vulnerability."""
        with pytest.raises(ValueError, match="Vulnerability .* not found"):
            self.editor.generate_vex_document(
                cve_bin_data=self.sample_cve_data,
                vuln_id="CVE-9999-99999",
                status=VEXStatus.NOT_AFFECTED
            )
    
    def test_generate_vex_from_file(self):
        """Test generating VEX document from file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_cve_data, f)
            temp_file = f.name
        
        try:
            vex_json = self.editor.generate_vex_from_file(
                input_file=temp_file,
                vuln_id="CVE-2021-44228",
                status=VEXStatus.FIXED
            )
            
            # Validate it's valid JSON and has expected structure
            vex_data = json.loads(vex_json)
            assert "bomFormat" in vex_data
            assert "vulnerabilities" in vex_data
        finally:
            os.unlink(temp_file)
    
    def test_all_statuses_work(self):
        """Test that all valid statuses can be used to generate VEX documents."""
        for status in VEXEditor.VALID_STATUSES:
            justification = VEXJustification.VULNERABLE_CODE_NOT_PRESENT if status == VEXStatus.NOT_AFFECTED else None
            
            vex_json = self.editor.generate_vex_document(
                cve_bin_data=self.sample_cve_data,
                vuln_id="CVE-2021-44228",
                status=status,
                justification=justification
            )
            
            # Should be valid JSON
            vex_data = json.loads(vex_json)
            assert "bomFormat" in vex_data
            assert "vulnerabilities" in vex_data
    
    def test_all_justifications_work(self):
        """Test that all valid justifications can be used."""
        for justification in VEXEditor.VALID_JUSTIFICATIONS:
            vex_json = self.editor.generate_vex_document(
                cve_bin_data=self.sample_cve_data,
                vuln_id="CVE-2021-44228",
                status=VEXStatus.NOT_AFFECTED,
                justification=justification
            )
            
            # Should be valid JSON
            vex_data = json.loads(vex_json)
            assert "bomFormat" in vex_data
            assert "vulnerabilities" in vex_data
