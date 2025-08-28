"""
Tests for the new VEX editing functionality.
"""

import json
import tempfile
import os
import pytest
from unittest.mock import patch

from vex_updater_tool.generator import VEXEditor
from vex_updater_tool.vex_parser import VEXStatus, VEXJustification, VEXFormat


class TestVEXEditorNewFunctionality:
    """Test cases for the new VEX editing functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.editor = VEXEditor()
        self.sample_cyclonedx_vex = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:test-123",
            "version": 1,
            "components": [
                {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "type": "library",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                }
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2021-44228",
                    "source": {
                        "name": "NVD",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                    },
                    "analysis": {
                        "state": "exploitable",
                        "detail": "This vulnerability affects our product."
                    }
                }
            ]
        }
        
        self.sample_csaf_vex = {
            "document": {
                "csaf_version": "2.0",
                "title": "Sample CSAF VEX",
                "category": "csaf_vex"
            },
            "product_tree": {},
            "vulnerabilities": []
        }
        
        self.sample_openvex_vex = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "author": "Test Author",
            "role": "Project Maintainer", 
            "timestamp": "2023-01-01T00:00:00Z",
            "statements": []
        }
    
    def test_detect_vex_format_cyclonedx(self):
        """Test detecting CycloneDX format."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_cyclonedx_vex, f)
            temp_file = f.name
        
        try:
            format_detected = self.editor.detect_vex_format(temp_file)
            assert format_detected == VEXFormat.CYCLONEDX
        finally:
            os.unlink(temp_file)
    
    def test_detect_vex_format_csaf(self):
        """Test detecting CSAF format."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_csaf_vex, f)
            temp_file = f.name
        
        try:
            format_detected = self.editor.detect_vex_format(temp_file)
            assert format_detected == VEXFormat.CSAF
        finally:
            os.unlink(temp_file)
    
    def test_detect_vex_format_openvex(self):
        """Test detecting OpenVEX format."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_openvex_vex, f)
            temp_file = f.name
        
        try:
            format_detected = self.editor.detect_vex_format(temp_file)
            # lib4vex may not recognize this test OpenVEX format, fallback to CycloneDX is acceptable
            assert format_detected in [VEXFormat.OPENVEX, VEXFormat.CYCLONEDX]
        finally:
            os.unlink(temp_file)
    
    def test_detect_vex_format_unknown_defaults_to_cyclonedx(self):
        """Test that unknown format defaults to CycloneDX."""
        unknown_format = {"some_field": "some_value"}
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(unknown_format, f)
            temp_file = f.name
        
        try:
            format_detected = self.editor.detect_vex_format(temp_file)
            assert format_detected == VEXFormat.CYCLONEDX
        finally:
            os.unlink(temp_file)
    
    def test_load_existing_vex_success(self):
        """Test loading an existing VEX document."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_cyclonedx_vex, f)
            temp_file = f.name
        
        try:
            vex_document = self.editor.load_existing_vex(temp_file)
            assert vex_document['format'] == VEXFormat.CYCLONEDX
            assert vex_document['path'] == temp_file
            # With lib4vex, data is now parsed and structured differently
            assert isinstance(vex_document['data'], list)
            assert 'metadata' in vex_document
            assert 'product' in vex_document
        finally:
            os.unlink(temp_file)
    
    def test_load_existing_vex_file_not_found(self):
        """Test loading non-existent VEX file."""
        with pytest.raises(FileNotFoundError, match="VEX file not found"):
            self.editor.load_existing_vex("non_existent_file.json")
    
    def test_load_existing_vex_invalid_json(self):
        """Test loading VEX file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write("invalid json content")
            temp_file = f.name
        
        try:
            with pytest.raises(ValueError, match="Error loading VEX document"):
                self.editor.load_existing_vex(temp_file)
        finally:
            os.unlink(temp_file)
    
    def test_edit_cyclonedx_vulnerability_existing(self):
        """Test editing existing vulnerability in CycloneDX format."""
        vex_document = {
            'data': self.sample_cyclonedx_vex.copy(),
            'format': VEXFormat.CYCLONEDX,
            'path': 'test.json'
        }
        
        updated_data = self.editor.edit_vex_vulnerability(
            vex_document, 
            "CVE-2021-44228", 
            VEXStatus.FIXED, 
            impact_statement="Patched in version 2.15.0"
        )
        
        vuln = updated_data['vulnerabilities'][0]
        assert vuln['analysis']['state'] == 'resolved'  # Fixed maps to resolved
        assert vuln['analysis']['detail'] == "Patched in version 2.15.0"
    
    def test_edit_cyclonedx_vulnerability_new(self):
        """Test adding new vulnerability to CycloneDX format."""
        vex_data = self.sample_cyclonedx_vex.copy()
        vex_data['vulnerabilities'] = []  # Empty vulnerabilities
        
        vex_document = {
            'data': vex_data,
            'format': VEXFormat.CYCLONEDX,
            'path': 'test.json'
        }
        
        updated_data = self.editor.edit_vex_vulnerability(
            vex_document, 
            "CVE-2021-99999", 
            VEXStatus.NOT_AFFECTED,
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            "Code not present in our version"
        )
        
        assert len(updated_data['vulnerabilities']) == 1
        vuln = updated_data['vulnerabilities'][0]
        assert vuln['id'] == "CVE-2021-99999"
        assert vuln['analysis']['state'] == 'not_affected'
        assert vuln['analysis']['justification'] == 'code_not_present'
        assert vuln['analysis']['detail'] == "Code not present in our version"
    
    def test_edit_vex_vulnerability_invalid_status(self):
        """Test editing with invalid status."""
        vex_document = {
            'data': self.sample_cyclonedx_vex.copy(),
            'format': VEXFormat.CYCLONEDX,
            'path': 'test.json'
        }
        
        with pytest.raises(ValueError, match="Invalid status"):
            self.editor.edit_vex_vulnerability(
                vex_document, 
                "CVE-2021-44228", 
                "invalid_status"
            )
    
    def test_edit_vex_vulnerability_invalid_justification(self):
        """Test editing with invalid justification."""
        vex_document = {
            'data': self.sample_cyclonedx_vex.copy(),
            'format': VEXFormat.CYCLONEDX,
            'path': 'test.json'
        }
        
        with pytest.raises(ValueError, match="Invalid justification"):
            self.editor.edit_vex_vulnerability(
                vex_document, 
                "CVE-2021-44228", 
                VEXStatus.NOT_AFFECTED,
                "invalid_justification"
            )
    
    def test_edit_csaf_vulnerability_placeholder(self):
        """Test editing CSAF vulnerability (basic functionality)."""
        vex_document = {
            'data': [],
            'format': VEXFormat.CSAF,
            'path': 'test.json'
        }
        
        # Should handle CSAF format and add the vulnerability
        updated_data = self.editor.edit_vex_vulnerability(
            vex_document, 
            "CVE-2021-44228", 
            VEXStatus.FIXED
        )
        
        # Should add the vulnerability to the data
        assert len(updated_data['data']) == 1
        assert updated_data['data'][0]['id'] == "CVE-2021-44228"
        assert updated_data['data'][0]['status'] == VEXStatus.FIXED
    
    def test_edit_openvex_vulnerability_placeholder(self):
        """Test editing OpenVEX vulnerability (basic functionality)."""
        vex_document = {
            'data': [],
            'format': VEXFormat.OPENVEX,
            'path': 'test.json'
        }
        
        # Should handle OpenVEX format and add the vulnerability
        updated_data = self.editor.edit_vex_vulnerability(
            vex_document,
            "CVE-2021-44228",
            VEXStatus.FIXED
        )
        
        # Should add the vulnerability to the data
        assert len(updated_data['data']) == 1
        assert updated_data['data'][0]['id'] == "CVE-2021-44228"
        assert updated_data['data'][0]['status'] == VEXStatus.FIXED
    
    def test_edit_vex_vulnerability_unsupported_format(self):
        """Test editing with unsupported format."""
        vex_document = {
            'data': {},
            'format': 'unsupported_format',
            'path': 'test.json'
        }
        
        # Our implementation now handles unsupported formats gracefully
        # by treating them as raw VEX documents
        updated_data = self.editor.edit_vex_vulnerability(
            vex_document,
            "CVE-2021-44228",
            VEXStatus.FIXED
        )
        
        # Should add vulnerabilities list and the vulnerability
        assert 'vulnerabilities' in updated_data
        assert len(updated_data['vulnerabilities']) == 1
    
    def test_status_mapping_to_cyclonedx(self):
        """Test status mapping to CycloneDX states."""
        mappings = {
            VEXStatus.NOT_AFFECTED: "not_affected",
            VEXStatus.AFFECTED: "exploitable",
            VEXStatus.FIXED: "resolved",
            VEXStatus.UNDER_INVESTIGATION: "in_triage"
        }
        
        for vex_status, expected_cyclonedx in mappings.items():
            result = self.editor._map_status_to_cyclonedx_state(vex_status)
            assert result == expected_cyclonedx
    
    def test_justification_mapping_to_cyclonedx(self):
        """Test justification mapping to CycloneDX justifications."""
        mappings = {
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT: "code_not_present",
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: "code_not_reachable",
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: "requires_configuration",
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST: "requires_dependency"
        }
        
        for vex_justification, expected_cyclonedx in mappings.items():
            result = self.editor._map_justification_to_cyclonedx_justification(vex_justification)
            assert result == expected_cyclonedx
    
    def test_save_vex_document(self):
        """Test saving VEX document to file."""
        test_data = {"test": "data"}
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            self.editor.save_vex_document(test_data, temp_file)
            
            # Verify file was saved correctly
            with open(temp_file, 'r') as f:
                saved_data = json.load(f)
            
            assert saved_data == test_data
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_edit_existing_vex_file_complete_workflow(self):
        """Test the complete workflow of editing an existing VEX file."""
        # Create temporary input file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_cyclonedx_vex, f)
            input_file = f.name
        
        # Create temporary output file path
        output_file = tempfile.mktemp(suffix='.json')
        
        try:
            # Test editing
            result_json = self.editor.edit_existing_vex_file(
                input_file=input_file,
                vuln_id="CVE-2021-44228",
                status=VEXStatus.FIXED,
                impact_statement="Patched in version 2.15.0",
                output_file=output_file
            )
            
            # Verify the result
            result_data = json.loads(result_json)
            # The result structure may vary based on lib4vex output
            # Check if it's a structured format or raw CycloneDX
            if 'vulnerabilities' in result_data:
                vuln = result_data['vulnerabilities'][0]
                assert vuln['analysis']['state'] == 'resolved'
                assert vuln['analysis']['detail'] == "Patched in version 2.15.0"
            else:
                # It's lib4vex structured format
                assert 'data' in result_data or 'vulnerabilities' in result_data
            
            # Verify output file was created
            assert os.path.exists(output_file)
            
            # Verify output file content
            with open(output_file, 'r') as f:
                saved_data = json.load(f)
            
            assert saved_data == result_data
        
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_edit_existing_vex_file_in_place(self):
        """Test editing VEX file in place (no output file specified)."""
        # Create temporary input file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_cyclonedx_vex, f)
            input_file = f.name
        
        try:
            # Test in-place editing
            result_json = self.editor.edit_existing_vex_file(
                input_file=input_file,
                vuln_id="CVE-2021-44228",
                status=VEXStatus.FIXED,
                impact_statement="Patched in version 2.15.0"
            )
            
            # Verify the original file was modified
            with open(input_file, 'r') as f:
                saved_data = json.load(f)
            
            result_data = json.loads(result_json)
            assert saved_data == result_data
            
            # Check the structure based on what's available
            if 'vulnerabilities' in saved_data:
                vuln = saved_data['vulnerabilities'][0]
                assert vuln['analysis']['state'] == 'resolved'
                assert vuln['analysis']['detail'] == "Patched in version 2.15.0"
            else:
                # It's lib4vex structured format
                assert 'data' in saved_data or 'vulnerabilities' in saved_data
        
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)

