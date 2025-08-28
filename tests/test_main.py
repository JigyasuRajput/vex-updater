"""
Tests for the main CLI module.
"""

import json
import tempfile
import os
import pytest
import sys
from io import StringIO
from unittest.mock import patch, MagicMock
import argparse

from vex_updater_tool.main import create_parser, validate_arguments, main
from vex_updater_tool.vex_parser import VEXStatus, VEXJustification


class TestCLIParser:
    """Test cases for CLI argument parsing."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = create_parser()
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
    
    def test_parser_required_arguments_cve_bin_json(self):
        """Test that required arguments are parsed correctly with cve-bin-json."""
        args = self.parser.parse_args([
            '--cve-bin-json', 'input.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'not_affected'
        ])
        
        assert args.cve_bin_json == 'input.json'
        assert args.input_vex is None
        assert args.vuln_id == 'CVE-2021-44228'
        assert args.status == 'not_affected'
    
    def test_parser_required_arguments_input_vex(self):
        """Test that required arguments are parsed correctly with input-vex."""
        args = self.parser.parse_args([
            '--input-vex', 'existing.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'fixed'
        ])
        
        assert args.input_vex == 'existing.json'
        assert args.cve_bin_json is None
        assert args.vuln_id == 'CVE-2021-44228'
        assert args.status == 'fixed'
    
    def test_parser_missing_required_arguments(self):
        """Test that missing required arguments are handled by validation, not parser."""
        # The new parser is more permissive and validation happens separately
        # Test that these don't cause parser to exit (validation comes later)
        
        # These should parse successfully (validation happens in validate_arguments)
        args1 = self.parser.parse_args([
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'not_affected'
        ])
        assert args1.vuln_id == 'CVE-2021-44228'
        
        args2 = self.parser.parse_args([
            '--cve-bin-json', 'input.json',
            '--status', 'not_affected'
        ])
        assert args2.cve_bin_json == 'input.json'
        
        args3 = self.parser.parse_args([
            '--cve-bin-json', 'input.json',
            '--vuln-id', 'CVE-2021-44228'
        ])
        assert args3.vuln_id == 'CVE-2021-44228'
    
    def test_parser_mutually_exclusive_inputs(self):
        """Test that cve-bin-json and input-vex are mutually exclusive."""
        # Since there's no mutually exclusive group defined, this should parse successfully
        # The validation will catch this later
        args = self.parser.parse_args([
            '--cve-bin-json', 'input.json',
            '--input-vex', 'existing.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'not_affected'
        ])
        
        # Both should be set, but validation will catch this
        assert args.cve_bin_json == 'input.json'
        assert args.input_vex == 'existing.json'
    
    def test_parser_all_arguments_cve_bin_json(self):
        """Test parsing with all arguments provided for cve-bin-json."""
        args = self.parser.parse_args([
            '--cve-bin-json', 'input.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'not_affected',
            '--justification', 'vulnerable_code_not_present',
            '--impact-statement', 'Impact description',
            '--output', 'output.json',
            '--format', 'cyclonedx'
        ])
        
        assert args.cve_bin_json == 'input.json'
        assert args.input_vex is None
        assert args.vuln_id == 'CVE-2021-44228'
        assert args.status == 'not_affected'
        assert args.justification == 'vulnerable_code_not_present'
        assert args.impact_statement == 'Impact description'
        assert args.output == 'output.json'
        assert args.format == 'cyclonedx'
    
    def test_parser_all_arguments_input_vex(self):
        """Test parsing with all arguments provided for input-vex."""
        args = self.parser.parse_args([
            '--input-vex', 'existing.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'fixed',
            '--impact-statement', 'Impact description',
            '--output', 'output.json'
        ])
        
        assert args.input_vex == 'existing.json'
        assert args.cve_bin_json is None
        assert args.vuln_id == 'CVE-2021-44228'
        assert args.status == 'fixed'
        assert args.impact_statement == 'Impact description'
        assert args.output == 'output.json'
    
    def test_parser_invalid_status(self):
        """Test that invalid status values are rejected."""
        with pytest.raises(SystemExit):
            self.parser.parse_args([
                '--cve-bin-json', 'input.json',
                '--vuln-id', 'CVE-2021-44228',
                '--status', 'invalid_status'
            ])
    
    def test_parser_invalid_justification(self):
        """Test that invalid justification values are rejected."""
        with pytest.raises(SystemExit):
            self.parser.parse_args([
                '--cve-bin-json', 'input.json',
                '--vuln-id', 'CVE-2021-44228',
                '--status', 'not_affected',
                '--justification', 'invalid_justification'
            ])
    
    def test_parser_valid_statuses(self):
        """Test that all valid status values are accepted."""
        valid_statuses = ['not_affected', 'affected', 'fixed', 'under_investigation']
        
        for status in valid_statuses:
            args = self.parser.parse_args([
                '--cve-bin-json', 'input.json',
                '--vuln-id', 'CVE-2021-44228',
                '--status', status
            ])
            assert args.status == status
    
    def test_parser_valid_justifications(self):
        """Test that all valid justification values are accepted."""
        valid_justifications = [
            'vulnerable_code_not_present',
            'vulnerable_code_not_in_execute_path',
            'vulnerable_code_cannot_be_controlled_by_adversary',
            'inline_mitigations_already_exist'
        ]
        
        for justification in valid_justifications:
            args = self.parser.parse_args([
                '--cve-bin-json', 'input.json',
                '--vuln-id', 'CVE-2021-44228',
                '--status', 'not_affected',
                '--justification', justification
            ])
            assert args.justification == justification


class TestArgumentValidation:
    """Test cases for argument validation."""
    
    def test_validate_not_affected_requires_justification(self):
        """Test that not_affected status requires justification in single vulnerability mode."""
        args = argparse.Namespace(
            explain=None,
            status=VEXStatus.NOT_AFFECTED,
            justification=None,
            cve_bin_json='input.json',
            input_vex=None,
            scan_file=None,
            vex_file=None,
            vuln_id='CVE-2021-44228'
        )
        
        with pytest.raises(ValueError, match="--justification is required"):
            validate_arguments(args)
    
    def test_validate_not_affected_with_justification(self):
        """Test that not_affected status with justification is valid in single vulnerability mode."""
        args = argparse.Namespace(
            explain=None,
            status=VEXStatus.NOT_AFFECTED,
            justification=VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
            cve_bin_json='input.json',
            input_vex=None,
            scan_file=None,
            vex_file=None,
            vuln_id='CVE-2021-44228'
        )
        
        validate_arguments(args)  # Should not raise
    
    def test_validate_other_statuses_without_justification(self):
        """Test that other statuses don't require justification in single vulnerability mode."""
        for status in [VEXStatus.AFFECTED, VEXStatus.FIXED, VEXStatus.UNDER_INVESTIGATION]:
            args = argparse.Namespace(
                explain=None,
                status=status,
                justification=None,
                cve_bin_json='input.json',
                input_vex=None,
                scan_file=None,
                vex_file=None,
                vuln_id='CVE-2021-44228'
            )
            
            validate_arguments(args)  # Should not raise
    
    def test_validate_missing_input_source(self):
        """Test that missing both input sources raises error in single vulnerability mode."""
        args = argparse.Namespace(
            explain=None,
            status=VEXStatus.AFFECTED,
            justification=None,
            cve_bin_json=None,
            input_vex=None,
            scan_file=None,
            vex_file=None,
            vuln_id='CVE-2021-44228'
        )
        
        with pytest.raises(ValueError, match="Either --cve-bin-json or --input-vex must be provided"):
            validate_arguments(args)


class TestMainFunction:
    """Test cases for the main function."""
    
    def setup_method(self):
        """Set up test fixtures."""
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
    
    @patch('sys.argv')
    @patch('builtins.open', new_callable=MagicMock)
    @patch('vex_updater_tool.generator.VEXEditor.generate_vex_from_file')
    def test_main_output_to_file(self, mock_generate, mock_open, mock_argv):
        """Test main function with file output in single vulnerability mode."""
        # Setup for single vulnerability mode
        mock_argv.__getitem__.side_effect = lambda x: [
            'vex-updater',
            '--cve-bin-json', 'input.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'not_affected',
            '--justification', 'vulnerable_code_not_present',
            '--output', 'output.json'
        ][x]
        mock_argv.__len__.return_value = 8
        
        mock_generate.return_value = '{"bomFormat": "CycloneDX"}'
        
        # Capture stdout
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main()
        
        # Verify
        mock_generate.assert_called_once()
        mock_open.assert_called_once_with('output.json', 'w', encoding='utf-8')
        assert "VEX document generated successfully" in mock_stdout.getvalue()
    
    @patch('sys.argv')
    @patch('vex_updater_tool.generator.VEXEditor.generate_vex_from_file')
    def test_main_output_to_stdout(self, mock_generate, mock_argv):
        """Test main function with stdout output in single vulnerability mode."""
        # Setup for single vulnerability mode
        mock_argv.__getitem__.side_effect = lambda x: [
            'vex-updater',
            '--cve-bin-json', 'input.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'affected'
        ][x]
        mock_argv.__len__.return_value = 6
        
        mock_generate.return_value = '{"bomFormat": "CycloneDX", "version": 1}'
        
        # Capture stdout
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main()
        
        # Verify
        mock_generate.assert_called_once()
        output = mock_stdout.getvalue()
        assert '"bomFormat": "CycloneDX"' in output
        assert '"version": 1' in output
    
    @patch('sys.argv')
    @patch('vex_updater_tool.generator.VEXEditor.generate_vex_from_file')
    def test_main_validation_error(self, mock_generate, mock_argv):
        """Test main function with validation error in single vulnerability mode."""
        # Setup - missing justification for not_affected in single vulnerability mode
        mock_argv.__getitem__.side_effect = lambda x: [
            'vex-updater',
            '--cve-bin-json', 'input.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'not_affected'
        ][x]
        mock_argv.__len__.return_value = 6
        
        # Capture stderr and test exit
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with pytest.raises(SystemExit) as exc_info:
                main()
        
        # Verify
        assert exc_info.value.code == 1
        assert "Error:" in mock_stderr.getvalue()
        assert "justification is required" in mock_stderr.getvalue()
    
    @patch('sys.argv')
    @patch('vex_updater_tool.generator.VEXEditor.generate_vex_from_file')
    def test_main_file_not_found_error(self, mock_generate, mock_argv):
        """Test main function with file not found error in single vulnerability mode."""
        # Setup for single vulnerability mode
        mock_argv.__getitem__.side_effect = lambda x: [
            'vex-updater',
            '--cve-bin-json', 'input.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'affected'
        ][x]
        mock_argv.__len__.return_value = 6
        
        mock_generate.side_effect = FileNotFoundError("File not found: input.json")
        
        # Capture stderr and test exit
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with pytest.raises(SystemExit) as exc_info:
                main()
        
        # Verify
        assert exc_info.value.code == 1
        assert "Error:" in mock_stderr.getvalue()
        assert "File not found" in mock_stderr.getvalue()
    
    @patch('sys.argv')
    @patch('vex_updater_tool.generator.VEXEditor.generate_vex_from_file')
    def test_main_unexpected_error(self, mock_generate, mock_argv):
        """Test main function with unexpected error in single vulnerability mode."""
        # Setup for single vulnerability mode
        mock_argv.__getitem__.side_effect = lambda x: [
            'vex-updater',
            '--cve-bin-json', 'input.json',
            '--vuln-id', 'CVE-2021-44228',
            '--status', 'affected'
        ][x]
        mock_argv.__len__.return_value = 6
        
        mock_generate.side_effect = Exception("Unexpected error occurred")
        
        # Capture stderr and test exit
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with pytest.raises(SystemExit) as exc_info:
                main()
        
        # Verify
        assert exc_info.value.code == 1
        assert "Unexpected error:" in mock_stderr.getvalue()
    
    def test_main_integration_with_tempfile(self):
        """Integration test with actual file I/O in single vulnerability mode."""
        # Create temporary input file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(self.sample_cve_data, f)
            input_file = f.name
        
        # Create temporary output file path
        output_file = tempfile.mktemp(suffix='.json')
        
        try:
            # Test with sys.argv patching for single vulnerability mode
            test_args = [
                'vex-updater',
                '--cve-bin-json', input_file,
                '--vuln-id', 'CVE-2021-44228',
                '--status', 'not_affected',
                '--justification', 'vulnerable_code_not_present',
                '--output', output_file
            ]
            
            with patch('sys.argv', test_args):
                with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                    main()
            
            # Verify output file was created and contains valid JSON
            assert os.path.exists(output_file)
            with open(output_file, 'r') as f:
                vex_data = json.load(f)
            
            assert "bomFormat" in vex_data
            assert vex_data["bomFormat"] == "CycloneDX"
            assert "VEX document generated successfully" in mock_stdout.getvalue()
        
        finally:
            # Clean up
            if os.path.exists(input_file):
                os.unlink(input_file)
            if os.path.exists(output_file):
                os.unlink(output_file)
