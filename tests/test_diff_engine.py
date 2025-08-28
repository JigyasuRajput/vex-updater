"""
Comprehensive tests for the VEX Diff Engine module.

This module tests the granular (CVE-ID, Component-PURL) matching logic
and ensures the diff engine correctly identifies new, existing, and stale vulnerabilities.
"""

import pytest
import json
import os
from typing import Dict, Any

from vex_updater_tool.diff_engine import (
    VulnerabilityDiffer, 
    DiffEngine,
    VulnerabilityRecord,
    ComponentVulnerability,
    VulnerabilityDiffResult,
    VulnerabilityDiff,
    DiffResult
)


class TestVulnerabilityDiffer:
    """Test cases for the enhanced VulnerabilityDiffer class."""
    
    def setup_method(self):
        """Set up test fixtures for each test."""
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        
        # Load test fixtures
        self.small_scan_data = self._load_fixture('small_scan_report.json')
        self.large_scan_data = self._load_fixture('large_scan_report.json')
        self.empty_vex_data = self._load_fixture('empty_cyclonedx_vex.json')
        self.partial_vex_data = self._load_fixture('partially_triaged_cyclonedx_vex.json')
        self.full_vex_data = self._load_fixture('fully_triaged_cyclonedx_vex.json')
        self.duplicate_scan_data = self._load_fixture('scan_with_duplicate_cves.json')
        self.partial_duplicate_vex_data = self._load_fixture('partial_vex_same_cves.json')
    
    def _load_fixture(self, filename: str) -> Dict[str, Any]:
        """Load a test fixture file."""
        fixture_path = os.path.join(self.fixtures_dir, filename)
        with open(fixture_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def test_granular_diff_matching(self):
        """Test that diff engine correctly matches (CVE-ID, Component-PURL) pairs."""
        differ = VulnerabilityDiffer(self.duplicate_scan_data, self.partial_duplicate_vex_data)
        result = differ.analyze()
        
        # Verify same CVE in different components handled separately
        assert len(result.new_vulns) == 2  # CVE-2021-44228 for log4j-api, CVE-2023-2976 for guava@30.0-jre
        assert len(result.existing_vulns) == 2  # CVE-2021-44228 for log4j-core, CVE-2023-2976 for guava@28.0-jre
        assert len(result.stale_vulns) == 0  # No stale vulnerabilities
        
        # Check specific new vulnerabilities
        new_vuln_keys = {(v.vulnerability_record.cve_id, v.component_identifier) for v in result.new_vulns}
        expected_new = {
            ('CVE-2021-44228', 'pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1'),
            ('CVE-2023-2976', 'pkg:maven/com.google.guava/guava@30.0-jre')
        }
        assert new_vuln_keys == expected_new
        
        # Check specific existing vulnerabilities
        existing_vuln_keys = {(v.vulnerability_record.cve_id, v.component_identifier) for v in result.existing_vulns}
        expected_existing = {
            ('CVE-2021-44228', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'),
            ('CVE-2023-2976', 'pkg:maven/com.google.guava/guava@28.0-jre')
        }
        assert existing_vuln_keys == expected_existing
    
    def test_empty_vex_with_small_scan(self):
        """Test empty VEX against small scan report."""
        differ = VulnerabilityDiffer(self.small_scan_data, self.empty_vex_data)
        result = differ.analyze()
        
        # All scan vulnerabilities should be new
        assert len(result.new_vulns) == 5  # All 5 vulnerabilities from small scan
        assert len(result.existing_vulns) == 0
        assert len(result.stale_vulns) == 0
        assert result.summary['new'] == 5
        assert result.summary['total_scan'] == 5
        assert result.summary['total_vex'] == 0
    
    def test_partial_vex_with_small_scan(self):
        """Test partially triaged VEX against small scan report."""
        differ = VulnerabilityDiffer(self.small_scan_data, self.partial_vex_data)
        result = differ.analyze()
        
        # Should have new, existing, and no stale
        assert len(result.new_vulns) == 3  # CVE-2022-23307, CVE-2021-4104, CVE-2021-44228 for log4j-api
        assert len(result.existing_vulns) == 2  # CVE-2021-44228 for log4j-core, CVE-2023-2976
        assert len(result.stale_vulns) == 0
        
        # Verify specific components
        new_cves = {v.vulnerability_record.cve_id for v in result.new_vulns}
        assert 'CVE-2022-23307' in new_cves
        assert 'CVE-2021-4104' in new_cves
        
        existing_cves = {v.vulnerability_record.cve_id for v in result.existing_vulns}
        assert 'CVE-2021-44228' in existing_cves
        assert 'CVE-2023-2976' in existing_cves
    
    def test_full_vex_with_small_scan(self):
        """Test fully triaged VEX against small scan report."""
        differ = VulnerabilityDiffer(self.small_scan_data, self.full_vex_data)
        result = differ.analyze()
        
        # Should have only existing vulnerabilities
        assert len(result.new_vulns) == 0
        assert len(result.existing_vulns) == 5  # All vulnerabilities already triaged
        assert len(result.stale_vulns) == 0
        assert result.summary['existing'] == 5
    
    def test_stale_vulnerabilities_detection(self):
        """Test detection of stale vulnerabilities in VEX."""
        # Create a scan with fewer vulnerabilities than VEX
        reduced_scan_data = {
            "vulnerabilities": [
                self.small_scan_data['vulnerabilities'][0]  # Only first vulnerability
            ]
        }
        
        differ = VulnerabilityDiffer(reduced_scan_data, self.partial_vex_data)
        result = differ.analyze()
        
        # Should have stale vulnerabilities
        assert len(result.new_vulns) == 0
        assert len(result.existing_vulns) == 1  # CVE-2021-44228 for log4j-core
        assert len(result.stale_vulns) == 1   # CVE-2023-2976 not in reduced scan
        
        stale_cve = result.stale_vulns[0].vulnerability_record.cve_id
        assert stale_cve == 'CVE-2023-2976'
    
    def test_vulnerability_details_retrieval(self):
        """Test getting vulnerability details for specific CVE-component pairs."""
        differ = VulnerabilityDiffer(self.small_scan_data, self.partial_vex_data)
        
        # Test retrieving details for existing vulnerability
        details = differ.get_vulnerability_details(
            'CVE-2021-44228', 
            'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'
        )
        assert details is not None
        assert details.vulnerability_record.cve_id == 'CVE-2021-44228'
        assert details.vulnerability_record.component_name == 'log4j-core'
        assert details.vulnerability_record.component_version == '2.14.1'
        
        # Test retrieving details for non-existent combination
        details = differ.get_vulnerability_details(
            'CVE-9999-9999', 
            'pkg:maven/nonexistent/component@1.0.0'
        )
        assert details is None
    
    def test_component_vulnerability_structure(self):
        """Test the ComponentVulnerability data structure."""
        differ = VulnerabilityDiffer(self.small_scan_data, self.empty_vex_data)
        result = differ.analyze()
        
        # Check structure of ComponentVulnerability objects
        vuln = result.new_vulns[0]
        assert hasattr(vuln, 'vulnerability_record')
        assert hasattr(vuln, 'component_identifier')
        
        record = vuln.vulnerability_record
        assert hasattr(record, 'cve_id')
        assert hasattr(record, 'component_name')
        assert hasattr(record, 'component_version')
        assert hasattr(record, 'component_purl')
        assert hasattr(record, 'description')
        assert hasattr(record, 'severity')
        
        # Verify data types
        assert isinstance(record.cve_id, str)
        assert isinstance(record.component_name, str)
        assert isinstance(record.component_version, str)
        assert isinstance(record.component_purl, str)
        assert isinstance(vuln.component_identifier, str)
    
    def test_malformed_scan_data_handling(self):
        """Test handling of malformed scan data."""
        malformed_scan = self._load_fixture('malformed_scan.json')
        
        differ = VulnerabilityDiffer(malformed_scan, self.empty_vex_data)
        result = differ.analyze()
        
        # Should handle malformed data gracefully
        # Only valid vulnerabilities should be processed
        assert len(result.new_vulns) == 0  # No valid CVE IDs in malformed data
        assert result.summary['total_scan'] == 0
    
    def test_different_scan_formats(self):
        """Test handling of different scan data formats."""
        # Test with 'results' key instead of 'vulnerabilities'
        results_format = {
            'results': self.small_scan_data['vulnerabilities'][:2]
        }
        
        differ = VulnerabilityDiffer(results_format, self.empty_vex_data)
        result = differ.analyze()
        
        assert len(result.new_vulns) == 2
        assert result.summary['total_scan'] == 2
        
        # Test with 'data' key
        data_format = {
            'data': self.small_scan_data['vulnerabilities'][:1]
        }
        
        differ = VulnerabilityDiffer(data_format, self.empty_vex_data)
        result = differ.analyze()
        
        assert len(result.new_vulns) == 1
        assert result.summary['total_scan'] == 1
    
    def test_missing_component_purl_handling(self):
        """Test handling of missing component PURL."""
        scan_without_purl = {
            'vulnerabilities': [
                {
                    'cve_id': 'CVE-2021-99999',
                    'description': 'Test vulnerability',
                    'severity': 'high',
                    'component': {
                        'name': 'test-component',
                        'version': '1.0.0'
                        # No PURL field
                    }
                }
            ]
        }
        
        differ = VulnerabilityDiffer(scan_without_purl, self.empty_vex_data)
        result = differ.analyze()
        
        assert len(result.new_vulns) == 1
        vuln = result.new_vulns[0]
        
        # Should generate a basic PURL
        expected_purl = 'pkg:generic/test-component@1.0.0'
        assert vuln.vulnerability_record.component_purl == expected_purl
        assert vuln.component_identifier == expected_purl


class TestDiffEngine:
    """Test cases for the standard DiffEngine class for backward compatibility."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.diff_engine = DiffEngine()
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        
        # Sample vulnerability data in standard format
        self.sample_scan_vulns = [
            {
                'vuln_id': 'CVE-2021-44228',
                'description': 'Log4j RCE vulnerability',
                'component': {
                    'name': 'log4j-core',
                    'version': '2.14.1'
                }
            },
            {
                'vuln_id': 'CVE-2023-2976',
                'description': 'Guava temp directory vulnerability',
                'component': {
                    'name': 'guava',
                    'version': '28.0-jre'
                }
            }
        ]
        
        self.sample_vex_vulns = [
            {
                'id': 'CVE-2021-44228',
                'status': 'fixed',
                'description': 'Log4j RCE vulnerability'
            }
        ]
    
    def test_compare_scan_with_vex(self):
        """Test standard comparison functionality."""
        result = self.diff_engine.compare_scan_with_vex(
            self.sample_scan_vulns, 
            self.sample_vex_vulns
        )
        
        assert isinstance(result, DiffResult)
        assert len(result.new_vulnerabilities) == 1  # CVE-2023-2976
        assert len(result.unchanged_vulnerabilities) == 1  # CVE-2021-44228
        assert len(result.removed_vulnerabilities) == 0
        assert len(result.updated_vulnerabilities) == 0
        
        # Check summary
        assert result.summary['new'] == 1
        assert result.summary['unchanged'] == 1
        assert result.summary['removed'] == 0
        assert result.summary['updated'] == 0
    
    def test_vulnerability_changes_analysis(self):
        """Test analysis of vulnerability changes."""
        scan_info = {
            'vuln_id': 'CVE-2021-44228',
            'component': {'version': '2.14.1'}
        }
        vex_info = {
            'id': 'CVE-2021-44228',
            'status': 'under_investigation'
        }
        
        needs_update = self.diff_engine._analyze_vulnerability_changes(scan_info, vex_info)
        assert needs_update is True  # under_investigation status should trigger update
        
        # Test with fixed status
        vex_info['status'] = 'fixed'
        needs_update = self.diff_engine._analyze_vulnerability_changes(scan_info, vex_info)
        assert needs_update is False  # fixed status should not trigger update
    
    def test_diff_summary_text_generation(self):
        """Test generation of human-readable diff summary."""
        result = self.diff_engine.compare_scan_with_vex(
            self.sample_scan_vulns, 
            self.sample_vex_vulns
        )
        
        summary_text = self.diff_engine.get_diff_summary_text(result)
        
        assert "VEX Update Analysis Summary" in summary_text
        assert "New vulnerabilities to add: 1" in summary_text
        assert "Vulnerabilities up to date: 1" in summary_text
    
    def test_actionable_items_generation(self):
        """Test generation of actionable items from diff results."""
        result = self.diff_engine.compare_scan_with_vex(
            self.sample_scan_vulns, 
            self.sample_vex_vulns
        )
        
        actionable_items = self.diff_engine.get_actionable_items(result)
        
        assert len(actionable_items) == 1  # Only new vulnerability should be actionable
        
        item = actionable_items[0]
        assert item['priority'] == 'high'
        assert item['type'] == 'new'
        assert item['vuln_id'] == 'CVE-2023-2976'
        assert 'Add to VEX' in item['action']
    
    def test_removed_vulnerabilities(self):
        """Test detection of removed vulnerabilities."""
        # VEX has more vulnerabilities than scan
        extended_vex_vulns = self.sample_vex_vulns + [
            {
                'id': 'CVE-2022-99999',
                'status': 'not_affected',
                'description': 'Old vulnerability'
            }
        ]
        
        result = self.diff_engine.compare_scan_with_vex(
            self.sample_scan_vulns, 
            extended_vex_vulns
        )
        
        assert len(result.removed_vulnerabilities) == 1
        assert result.removed_vulnerabilities[0].vuln_id == 'CVE-2022-99999'
        assert result.summary['removed'] == 1
    
    def test_empty_inputs(self):
        """Test handling of empty inputs."""
        # Empty scan, empty VEX
        result = self.diff_engine.compare_scan_with_vex([], [])
        assert all(len(getattr(result, attr)) == 0 for attr in 
                  ['new_vulnerabilities', 'updated_vulnerabilities', 
                   'removed_vulnerabilities', 'unchanged_vulnerabilities'])
        
        # Empty scan, non-empty VEX
        result = self.diff_engine.compare_scan_with_vex([], self.sample_vex_vulns)
        assert len(result.removed_vulnerabilities) == 1
        assert len(result.new_vulnerabilities) == 0
        
        # Non-empty scan, empty VEX
        result = self.diff_engine.compare_scan_with_vex(self.sample_scan_vulns, [])
        assert len(result.new_vulnerabilities) == 2
        assert len(result.removed_vulnerabilities) == 0


class TestDiffEnginePerformance:
    """Performance tests for diff engine with large datasets."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        self.large_scan_data = self._load_fixture('large_scan_report.json')
        self.empty_vex_data = self._load_fixture('empty_cyclonedx_vex.json')
    
    def _load_fixture(self, filename: str) -> Dict[str, Any]:
        """Load a test fixture file."""
        fixture_path = os.path.join(self.fixtures_dir, filename)
        with open(fixture_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def test_large_scan_performance(self):
        """Test performance with large scan report."""
        import time
        
        start_time = time.time()
        differ = VulnerabilityDiffer(self.large_scan_data, self.empty_vex_data)
        result = differ.analyze()
        end_time = time.time()
        
        # Should complete within reasonable time (< 1 second for 10 vulnerabilities)
        elapsed_time = end_time - start_time
        assert elapsed_time < 1.0, f"Large scan analysis took too long: {elapsed_time:.2f}s"
        
        # Verify results
        assert len(result.new_vulns) == 10  # All vulnerabilities should be new
        assert result.summary['total_scan'] == 10
    
    def test_memory_efficiency(self):
        """Test memory efficiency with large datasets."""
        # This test ensures the diff engine doesn't create unnecessary copies
        differ = VulnerabilityDiffer(self.large_scan_data, self.empty_vex_data)
        
        # Check that original data is preserved
        assert differ.scan_data is self.large_scan_data
        assert differ.vex_data is self.empty_vex_data
        
        # Analyze should not modify original data
        original_scan_copy = json.dumps(self.large_scan_data, sort_keys=True)
        original_vex_copy = json.dumps(self.empty_vex_data, sort_keys=True)
        
        differ.analyze()
        
        assert json.dumps(differ.scan_data, sort_keys=True) == original_scan_copy
        assert json.dumps(differ.vex_data, sort_keys=True) == original_vex_copy


if __name__ == '__main__':
    pytest.main([__file__])
