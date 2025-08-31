"""
Test the debug option functionality.
"""

import pytest
import logging
import tempfile
import os
from unittest.mock import patch, MagicMock
from vex_updater_tool.main import setup_logging, create_parser


class TestDebugOption:
    """Test the debug option functionality."""
    
    def test_debug_option_in_parser(self):
        """Test that the debug option is properly added to the parser."""
        parser = create_parser()
        args = parser.parse_args(['--debug', 'debug'])
        assert args.debug == 'debug'
    
    def test_debug_option_default(self):
        """Test that the debug option defaults to warning."""
        parser = create_parser()
        args = parser.parse_args([])
        assert args.debug == 'warning'
    
    def test_debug_option_choices(self):
        """Test that all debug level choices are accepted."""
        parser = create_parser()
        valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
        
        for level in valid_levels:
            args = parser.parse_args(['--debug', level])
            assert args.debug == level
    
    def test_debug_option_invalid_choice(self):
        """Test that invalid debug levels are rejected."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['--debug', 'invalid'])
    
    def test_setup_logging_debug_level(self):
        """Test that setup_logging configures debug level correctly."""
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                setup_logging('debug')
                
                # Check that basicConfig was called with debug level
                mock_basic_config.assert_called_once()
                call_args = mock_basic_config.call_args
                assert call_args[1]['level'] == logging.DEBUG
    
    def test_setup_logging_info_level(self):
        """Test that setup_logging configures info level correctly."""
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                setup_logging('info')
                
                # Check that basicConfig was called with info level
                mock_basic_config.assert_called_once()
                call_args = mock_basic_config.call_args
                assert call_args[1]['level'] == logging.INFO
    
    def test_setup_logging_warning_level(self):
        """Test that setup_logging configures warning level correctly."""
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                setup_logging('warning')
                
                # Check that basicConfig was called with warning level
                mock_basic_config.assert_called_once()
                call_args = mock_basic_config.call_args
                assert call_args[1]['level'] == logging.WARNING
    
    def test_setup_logging_error_level(self):
        """Test that setup_logging configures error level correctly."""
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                setup_logging('error')
                
                # Check that basicConfig was called with error level
                mock_basic_config.assert_called_once()
                call_args = mock_basic_config.call_args
                assert call_args[1]['level'] == logging.ERROR
    
    def test_setup_logging_critical_level(self):
        """Test that setup_logging configures critical level correctly."""
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                setup_logging('critical')
                
                # Check that basicConfig was called with critical level
                mock_basic_config.assert_called_once()
                call_args = mock_basic_config.call_args
                assert call_args[1]['level'] == logging.CRITICAL
    
    def test_setup_logging_invalid_level(self):
        """Test that setup_logging handles invalid levels gracefully."""
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                setup_logging('invalid')
                
                # Should default to INFO level
                mock_basic_config.assert_called_once()
                call_args = mock_basic_config.call_args
                assert call_args[1]['level'] == logging.INFO
    
    def test_setup_logging_logger_configuration(self):
        """Test that setup_logging configures all application loggers."""
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                setup_logging('debug')
                
                # Check that all application loggers were configured
                expected_loggers = [
                    'vex_updater_tool',
                    'vex_updater_tool.main',
                    'vex_updater_tool.updater',
                    'vex_updater_tool.scan_parser',
                    'vex_updater_tool.vex_parser',
                    'vex_updater_tool.diff_engine',
                    'vex_updater_tool.interactive_triage',
                    'vex_updater_tool.user_guidance',
                    'vex_updater_tool.generator'
                ]
                
                assert mock_get_logger.call_count == len(expected_loggers)
                for logger_name in expected_loggers:
                    mock_get_logger.assert_any_call(logger_name)
