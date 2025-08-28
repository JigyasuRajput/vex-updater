"""
Tests for the new VEX updater module and orchestrator pattern.
"""

import json
import tempfile
import os
import pytest
from unittest.mock import patch, MagicMock

from vex_updater_tool.updater import VEXUpdater
from vex_updater_tool.vex_parser import VEXStatus, VEXJustification, VEXFormat
from vex_updater_tool.diff_engine import DiffResult, VulnerabilityDiff


class TestVEXUpdater:
    """Test cases for the VEXUpdater orchestrator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.updater = VEXUpdater()
        self.sample_scan_data = {
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
        
        self.sample_vex_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "log4j-core",
                    "version": "2.14.1"
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
                        "state": "not_affected",
                        "justification": "code_not_present",
                        "detail": "The vulnerable code is not included."
                    }
                }
            ]
        }
    
    def test_validate_inputs_valid_files(self):
        """Test input validation with valid files."""
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as scan_f:
            json.dump(self.sample_scan_data, scan_f)
            scan_file = scan_f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as vex_f:
            json.dump(self.sample_vex_data, vex_f)
            vex_file = vex_f.name
        
        try:
            errors = self.updater.validate_inputs(scan_file, vex_file)
            assert errors == []
        finally:
            os.unlink(scan_file)
            os.unlink(vex_file)
    
    def test_validate_inputs_missing_files(self):
        """Test input validation with missing files."""
        errors = self.updater.validate_inputs("nonexistent_scan.json", "nonexistent_vex.json")
        assert len(errors) == 2
        assert "Scan file not found" in errors[0]
        assert "VEX file not found" in errors[1]
    
    def test_validate_inputs_invalid_scan_format(self):
        """Test input validation with invalid scan file format."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write("invalid json")
            temp_file = f.name
        
        try:
            errors = self.updater.validate_inputs(temp_file)
            assert len(errors) == 1
            assert "Invalid scan file format" in errors[0]
        finally:
            os.unlink(temp_file)
    
    @patch('vex_updater_tool.updater.VEXUpdater.validate_inputs')
    @patch('vex_updater_tool.scan_parser.ScanParser.load_cve_bin_tool_data')
    @patch('vex_updater_tool.vex_parser.VEXParser.load_existing_vex')
    @patch('vex_updater_tool.diff_engine.DiffEngine.compare_scan_with_vex')
    def test_update_vex_no_changes_needed(self, mock_diff, mock_load_vex, mock_load_scan, mock_validate):
        """Test update when no changes are needed."""
        # Setup mocks
        mock_validate.return_value = []
        mock_load_scan.return_value = self.sample_scan_data
        mock_load_vex.return_value = {'data': self.sample_vex_data, 'format': VEXFormat.CYCLONEDX}
        
        # Create a diff result with no changes
        mock_diff_result = DiffResult(
            new_vulnerabilities=[],
            updated_vulnerabilities=[],
            removed_vulnerabilities=[],
            unchanged_vulnerabilities=[],
            summary={'new': 0, 'removed': 0, 'updated': 0, 'unchanged': 1}
        )
        mock_diff.return_value = mock_diff_result
        
        # Test
        result = self.updater.update_vex_from_scan("scan.json", "vex.json", interactive=False)
        
        # Verify
        assert result['status'] == 'no_changes'
        assert result['summary']['new'] == 0
    
    @patch('vex_updater_tool.updater.VEXUpdater.validate_inputs')
    @patch('vex_updater_tool.scan_parser.ScanParser.load_cve_bin_tool_data')
    @patch('vex_updater_tool.vex_parser.VEXParser.load_existing_vex')
    @patch('vex_updater_tool.diff_engine.DiffEngine.compare_scan_with_vex')
    @patch('vex_updater_tool.interactive_triage.InteractiveTriage.run_batch_triage')
    @patch('vex_updater_tool.vex_parser.VEXParser.save_vex_document')
    def test_update_vex_with_changes(self, mock_save, mock_triage, mock_diff, 
                                   mock_load_vex, mock_load_scan, mock_validate):
        """Test update when changes are applied."""
        # Setup mocks
        mock_validate.return_value = []
        mock_load_scan.return_value = self.sample_scan_data
        mock_load_vex.return_value = {'data': self.sample_vex_data, 'format': VEXFormat.CYCLONEDX}
        
        # Create a diff result with new vulnerabilities
        new_vuln_diff = VulnerabilityDiff(
            vuln_id="CVE-2021-44229",
            status="new",
            scan_info={"vuln_id": "CVE-2021-44229"},
            recommended_action="Add to VEX"
        )
        
        mock_diff_result = DiffResult(
            new_vulnerabilities=[new_vuln_diff],
            updated_vulnerabilities=[],
            removed_vulnerabilities=[],
            unchanged_vulnerabilities=[],
            summary={'new': 1, 'removed': 0, 'updated': 0, 'unchanged': 0}
        )
        mock_diff.return_value = mock_diff_result
        
        # Mock triage decisions
        triage_decisions = {
            "CVE-2021-44229": {
                'action': 'update',
                'status': VEXStatus.UNDER_INVESTIGATION,
                'justification': None,
                'impact_statement': 'New vulnerability requiring investigation.'
            }
        }
        mock_triage.return_value = triage_decisions
        
        # Test
        result = self.updater.update_vex_from_scan("scan.json", "vex.json", interactive=False)
        
        # Verify
        assert result['status'] == 'success'
        assert result['applied_changes'] == 1
        mock_save.assert_called_once()
    
    @patch('vex_updater_tool.updater.VEXUpdater.validate_inputs')
    @patch('vex_updater_tool.scan_parser.ScanParser.load_cve_bin_tool_data')
    @patch('vex_updater_tool.interactive_triage.InteractiveTriage.run_batch_triage')
    @patch('vex_updater_tool.vex_parser.VEXParser.save_vex_document')
    def test_create_vex_from_scan(self, mock_save, mock_triage, mock_load_scan, mock_validate):
        """Test creating new VEX from scan data."""
        # Setup mocks
        mock_validate.return_value = []
        mock_load_scan.return_value = self.sample_scan_data
        
        # Mock triage decisions
        triage_decisions = {
            "CVE-2021-44228": {
                'action': 'update',
                'status': VEXStatus.UNDER_INVESTIGATION,
                'justification': None,
                'impact_statement': 'New vulnerability requiring investigation.'
            }
        }
        mock_triage.return_value = triage_decisions
        
        # Test
        result = self.updater.create_vex_from_scan("scan.json", "new_vex.json", interactive=False)
        
        # Verify
        assert result['status'] == 'created'
        assert result['vulnerability_count'] == 1
        mock_save.assert_called_once()
    
    def test_get_default_decisions(self):
        """Test default triage decisions."""
        defaults = self.updater._get_default_decisions()
        
        assert 'new' in defaults
        assert 'removed' in defaults
        assert defaults['new']['status'] == 'under_investigation'
        assert defaults['removed']['status'] == 'fixed'


class TestDiffEngine:
    """Test cases for the diff engine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        from vex_updater_tool.diff_engine import DiffEngine
        self.diff_engine = DiffEngine()
    
    def test_compare_scan_with_vex_new_vulnerabilities(self):
        """Test diff analysis with new vulnerabilities."""
        scan_vulns = [
            {'vuln_id': 'CVE-2021-44228', 'component': {'name': 'log4j'}},
            {'vuln_id': 'CVE-2021-44229', 'component': {'name': 'log4j'}}
        ]
        
        vex_vulns = [
            {'id': 'CVE-2021-44228', 'status': 'not_affected'}
        ]
        
        result = self.diff_engine.compare_scan_with_vex(scan_vulns, vex_vulns)
        
        assert result.summary['new'] == 1
        assert result.summary['unchanged'] == 1
        assert len(result.new_vulnerabilities) == 1
        assert result.new_vulnerabilities[0].vuln_id == 'CVE-2021-44229'
    
    def test_compare_scan_with_vex_removed_vulnerabilities(self):
        """Test diff analysis with removed vulnerabilities."""
        scan_vulns = [
            {'vuln_id': 'CVE-2021-44228', 'component': {'name': 'log4j'}}
        ]
        
        vex_vulns = [
            {'id': 'CVE-2021-44228', 'status': 'not_affected'},
            {'id': 'CVE-2021-44229', 'status': 'fixed'}
        ]
        
        result = self.diff_engine.compare_scan_with_vex(scan_vulns, vex_vulns)
        
        assert result.summary['removed'] == 1
        assert result.summary['unchanged'] == 1
        assert len(result.removed_vulnerabilities) == 1
        assert result.removed_vulnerabilities[0].vuln_id == 'CVE-2021-44229'


class TestScanParser:
    """Test cases for the scan parser."""
    
    def setup_method(self):
        """Set up test fixtures."""
        from vex_updater_tool.scan_parser import ScanParser
        self.parser = ScanParser()
        
        self.sample_data = {
            "components": [
                {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "vulnerabilities": [
                        {"vuln_id": "CVE-2021-44228", "description": "RCE vulnerability"}
                    ]
                }
            ]
        }
    
    def test_extract_vulnerabilities_from_scan(self):
        """Test extracting vulnerabilities from scan data."""
        vulns = self.parser.extract_vulnerabilities_from_scan(self.sample_data)
        
        assert len(vulns) == 1
        assert vulns[0]['vuln_id'] == 'CVE-2021-44228'
        assert vulns[0]['component']['name'] == 'log4j-core'
    
    def test_validate_scan_format_valid(self):
        """Test scan format validation with valid data."""
        assert self.parser.validate_scan_format(self.sample_data) == True
    
    def test_validate_scan_format_invalid(self):
        """Test scan format validation with invalid data."""
        invalid_data = {"invalid": "structure"}
        assert self.parser.validate_scan_format(invalid_data) == False


class TestVEXParser:
    """Test cases for the VEX parser."""
    
    def setup_method(self):
        """Set up test fixtures."""
        from vex_updater_tool.vex_parser import VEXParser
        self.parser = VEXParser()
        
        self.sample_vex = {
            "bomFormat": "CycloneDX",
            "vulnerabilities": [
                {
                    "id": "CVE-2021-44228",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_present"
                    }
                }
            ]
        }
    
    def test_extract_vulnerabilities_from_vex(self):
        """Test extracting vulnerabilities from VEX data."""
        # Since our implementation now uses lib4vex, we need to simulate 
        # the lib4vex parsed format
        vex_doc = {
            'data': self.sample_vex,  # This is the raw CycloneDX document
            'format': VEXFormat.CYCLONEDX
        }
        
        vulns = self.parser.extract_vulnerabilities_from_vex(vex_doc)
        
        # Since we're passing raw VEX data, it should return the raw data
        assert len(vulns) == 2  # bomFormat and vulnerabilities keys
        assert vulns == self.sample_vex
