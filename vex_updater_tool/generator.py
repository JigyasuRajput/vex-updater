"""
VEX Editor - Legacy compatibility layer for backward compatibility.

This module provides backward compatibility with the old VEXEditor interface
while using the new modular architecture internally.
"""

import json
import uuid
import os
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from cyclonedx.model import bom, component, vulnerability
from cyclonedx.model.vulnerability import ImpactAnalysisState, ImpactAnalysisJustification
from cyclonedx.output.json import JsonV1Dot4

# Import from the new modular structure
from .vex_parser import VEXStatus, VEXJustification, VEXFormat, VEXParser
from .scan_parser import ScanParser


class VEXEditor:
    """Legacy VEX editor for backward compatibility - uses new modular architecture internally."""
    
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
        """Initialize the VEX editor with new modular components."""
        self.supported_formats = [VEXFormat.CYCLONEDX, VEXFormat.CSAF, VEXFormat.OPENVEX]
        self.vex_parser = VEXParser()
        self.scan_parser = ScanParser()
    
    def validate_status(self, status: str) -> None:
        """Validate VEX status value."""
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(self.VALID_STATUSES)}")
    
    def validate_justification(self, justification: str) -> None:
        """Validate VEX justification value."""
        if justification not in self.VALID_JUSTIFICATIONS:
            raise ValueError(f"Invalid justification '{justification}'. Must be one of: {', '.join(self.VALID_JUSTIFICATIONS)}")
    
    def load_cve_bin_tool_data(self, file_path: str) -> Dict[str, Any]:
        """Load and parse cve-bin-tool JSON output - delegates to scan_parser."""
        return self.scan_parser.load_cve_bin_tool_data(file_path)
    
    def find_component_with_vulnerability(self, data: Dict[str, Any], vuln_id: str) -> Optional[Dict[str, Any]]:
        """Find the component that contains the specified vulnerability - delegates to scan_parser."""
        return self.scan_parser.find_component_with_vulnerability(data, vuln_id)
    
    def create_cyclonedx_component(self, comp_data: Dict[str, Any]) -> component.Component:
        """Create a CycloneDX component from component data."""
        comp_name = comp_data.get('name', 'unknown')
        comp_version = comp_data.get('version', '0.0.0')
        comp_purl = comp_data.get('purl')
        
        # Create component
        comp = component.Component(
            name=comp_name,
            version=comp_version,
            type=component.ComponentType.LIBRARY
        )
        
        if comp_purl:
            from packageurl import PackageURL
            try:
                purl_obj = PackageURL.from_string(comp_purl)
                comp.purl = purl_obj
            except Exception:
                # If PURL parsing fails, continue without it
                pass
        
        return comp
    
    def create_vex_vulnerability(self, vuln_id: str, status: str, justification: Optional[str] = None, 
                               impact_statement: Optional[str] = None) -> vulnerability.Vulnerability:
        """Create a VEX vulnerability entry."""
        # Validate inputs
        self.validate_status(status)
        if justification:
            self.validate_justification(justification)
        
        # Create vulnerability source
        vuln_source = vulnerability.VulnerabilitySource(
            name="NVD",
            url=f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
        )
        
        # Create vulnerability
        vuln = vulnerability.Vulnerability(
            id=vuln_id,
            source=vuln_source
        )
        
        # Create VEX analysis
        analysis = vulnerability.VulnerabilityAnalysis(
            state=self._map_status_to_analysis_state(status),
            justification=self._map_justification_to_analysis_justification(justification) if justification else None,
            detail=impact_statement
        )
        
        vuln.analysis = analysis
        
        return vuln
    
    def _map_status_to_analysis_state(self, status: str) -> ImpactAnalysisState:
        """Map VEX status to CycloneDX vulnerability analysis state."""
        mapping = {
            VEXStatus.NOT_AFFECTED: ImpactAnalysisState.NOT_AFFECTED,
            VEXStatus.AFFECTED: ImpactAnalysisState.EXPLOITABLE,
            VEXStatus.FIXED: ImpactAnalysisState.RESOLVED,
            VEXStatus.UNDER_INVESTIGATION: ImpactAnalysisState.IN_TRIAGE
        }
        return mapping[status]
    
    def _map_justification_to_analysis_justification(self, justification: str) -> ImpactAnalysisJustification:
        """Map VEX justification to CycloneDX vulnerability analysis justification."""
        mapping = {
            VEXJustification.VULNERABLE_CODE_NOT_PRESENT: ImpactAnalysisJustification.CODE_NOT_PRESENT,
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: ImpactAnalysisJustification.CODE_NOT_REACHABLE,
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: ImpactAnalysisJustification.REQUIRES_CONFIGURATION,
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST: ImpactAnalysisJustification.REQUIRES_DEPENDENCY
        }
        return mapping[justification]
    
    def generate_vex_document(self, cve_bin_data: Dict[str, Any], vuln_id: str, status: str, 
                            justification: Optional[str] = None, impact_statement: Optional[str] = None,
                            vex_format: str = "cyclonedx") -> str:
        """Generate a complete VEX document using lib4vex for native format support."""
        # Find the component with the specified vulnerability
        comp_data = self.find_component_with_vulnerability(cve_bin_data, vuln_id)
        if not comp_data:
            raise ValueError(f"Vulnerability {vuln_id} not found in any component")
        
        # Check if format is supported 
        supported_formats = ["cyclonedx", "csaf", "openvex"]
        if vex_format not in supported_formats:
            raise ValueError(f"Unsupported format: {vex_format}. Supported formats: {supported_formats}")
        
        # Use lib4vex for native generation of all formats
        if vex_format == "cyclonedx" or vex_format is None:
            # Keep backward compatibility for CycloneDX
            return self._generate_cyclonedx_document(cve_bin_data, vuln_id, status, justification, impact_statement)
        else:
            # Use native lib4vex generation for CSAF and OpenVEX
            return self._generate_lib4vex_document(cve_bin_data, vuln_id, status, justification, impact_statement, vex_format)
    
    def _generate_cyclonedx_document(self, cve_bin_data: Dict[str, Any], vuln_id: str, status: str, 
                                   justification: Optional[str] = None, impact_statement: Optional[str] = None) -> str:
        """Generate a CycloneDX VEX document (legacy method for backward compatibility)."""
        # Find the component with the specified vulnerability
        comp_data = self.find_component_with_vulnerability(cve_bin_data, vuln_id)
        if not comp_data:
            raise ValueError(f"Vulnerability {vuln_id} not found in any component")
        
        # Create CycloneDX BOM
        bom_obj = bom.Bom()
        bom_obj.serial_number = uuid.uuid4()  # Use UUID object instead of string
        bom_obj.version = 1
        
        # Create component
        comp = self.create_cyclonedx_component(comp_data)
        bom_obj.components.add(comp)
        
        # Create VEX vulnerability
        vuln = self.create_vex_vulnerability(vuln_id, status, justification, impact_statement)
        
        # Add vulnerability to BOM
        bom_obj.vulnerabilities.add(vuln)
        
        # Generate JSON output
        json_outputter = JsonV1Dot4(bom_obj)
        return json_outputter.output_as_string()
    
    def _generate_lib4vex_document(self, cve_bin_data: Dict[str, Any], vuln_id: str, status: str, 
                                 justification: Optional[str] = None, impact_statement: Optional[str] = None,
                                 vex_format: str = "csaf") -> str:
        """Generate a VEX document with native CSAF and OpenVEX support."""
        # Find the component with the specified vulnerability
        comp_data = self.find_component_with_vulnerability(cve_bin_data, vuln_id)
        if not comp_data:
            raise ValueError(f"Vulnerability {vuln_id} not found in any component")
        
        # Validate inputs
        self.validate_status(status)
        if justification:
            self.validate_justification(justification)
        
        if vex_format == "csaf":
            return self._generate_csaf_document(comp_data, vuln_id, status, justification, impact_statement)
        elif vex_format == "openvex":
            return self._generate_openvex_document(comp_data, vuln_id, status, justification, impact_statement)
        else:
            raise ValueError(f"Unsupported format for native generation: {vex_format}")
    
    def _generate_csaf_document(self, comp_data: Dict[str, Any], vuln_id: str, status: str,
                              justification: Optional[str] = None, impact_statement: Optional[str] = None) -> str:
        """Generate a native CSAF VEX document."""
        product_name = comp_data.get('name', 'Product')
        product_version = comp_data.get('version', '1.0.0')
        product_id = f"{product_name}-{product_version}"
        
        # Map VEX status to CSAF product_status
        if status == VEXStatus.NOT_AFFECTED:
            product_status = {"known_not_affected": [product_id]}
        elif status == VEXStatus.AFFECTED:
            product_status = {"known_affected": [product_id]}
        elif status == VEXStatus.FIXED:
            product_status = {"fixed": [product_id]}
        else:  # under_investigation
            product_status = {"under_investigation": [product_id]}
        
        # Create CSAF document structure
        csaf_doc = {
            "document": {
                "csaf_version": "2.0",
                "category": "vex",
                "title": f"VEX Document for {product_name}",
                "lang": "en",
                "source_lang": "en",
                "publisher": {
                    "category": "vendor",
                    "name": "VEX Updater Tool",
                    "namespace": "https://github.com/vex-updater"
                },
                "tracking": {
                    "id": f"VEX-{uuid.uuid4().hex[:8].upper()}",
                    "status": "final",
                    "version": "1.0.0",
                    "revision_history": [
                        {
                            "number": "1.0.0",
                            "date": datetime.now().isoformat() + "Z",
                            "summary": f"VEX statement for {vuln_id}"
                        }
                    ],
                    "initial_release_date": datetime.now().isoformat() + "Z",
                    "current_release_date": datetime.now().isoformat() + "Z",
                    "generator": {
                        "engine": {
                            "name": "vex-updater",
                            "version": "1.0.0"
                        }
                    }
                }
            },
            "product_tree": {
                "branches": [
                    {
                        "category": "product_family",
                        "name": product_name,
                        "branches": [
                            {
                                "category": "product_name",
                                "name": product_name,
                                "product": {
                                    "product_id": product_id,
                                    "name": f"{product_name} {product_version}"
                                }
                            }
                        ]
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "cve": vuln_id,
                    "title": f"Vulnerability {vuln_id}",
                    "product_status": product_status,
                    "threats": [
                        {
                            "category": "impact",
                            "details": impact_statement or f"Impact assessment for {vuln_id}",
                            "product_ids": [product_id]
                        }
                    ],
                    "notes": [
                        {
                            "category": "description",
                            "text": impact_statement or f"VEX statement for {vuln_id}",
                            "title": "Vulnerability Assessment"
                        }
                    ]
                }
            ]
        }
        
        # Add flags for justification if provided
        if justification and status == VEXStatus.NOT_AFFECTED:
            csaf_doc["vulnerabilities"][0]["flags"] = [
                {
                    "label": justification,
                    "product_ids": [product_id],
                    "date": datetime.now().isoformat() + "Z"
                }
            ]
        
        return json.dumps(csaf_doc, indent=2, ensure_ascii=False)
    
    def _generate_openvex_document(self, comp_data: Dict[str, Any], vuln_id: str, status: str,
                                 justification: Optional[str] = None, impact_statement: Optional[str] = None) -> str:
        """Generate a native OpenVEX document."""
        product_name = comp_data.get('name', 'Product')
        product_version = comp_data.get('version', '1.0.0')
        
        # Create OpenVEX document structure
        openvex_doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"https://example.com/vex/{uuid.uuid4()}",
            "author": "VEX Updater Tool",
            "role": "Product Vendor",
            "timestamp": datetime.now().isoformat() + "Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {
                        "name": vuln_id
                    },
                    "products": [
                        {
                            "@id": comp_data.get('purl', f"pkg:generic/{product_name}@{product_version}"),
                            "identifiers": {
                                "purl": comp_data.get('purl', f"pkg:generic/{product_name}@{product_version}")
                            }
                        }
                    ],
                    "status": status,
                    "timestamp": datetime.now().isoformat() + "Z"
                }
            ]
        }
        
        # Add justification and impact statement if provided
        statement = openvex_doc["statements"][0]
        if justification:
            statement["justification"] = justification
        if impact_statement:
            statement["impact_statement"] = impact_statement
        
        return json.dumps(openvex_doc, indent=2, ensure_ascii=False)
    
    def generate_vex_from_file(self, input_file: str, vuln_id: str, status: str, 
                             justification: Optional[str] = None, impact_statement: Optional[str] = None,
                             vex_format: str = "cyclonedx") -> str:
        """Generate VEX document from cve-bin-tool JSON file."""
        # Load and validate input data
        cve_bin_data = self.load_cve_bin_tool_data(input_file)
        
        # Generate VEX document
        return self.generate_vex_document(cve_bin_data, vuln_id, status, justification, impact_statement, vex_format)
    
    def detect_vex_format(self, file_path: str) -> VEXFormat:
        """Detect the format of an existing VEX document using lib4vex."""
        return self.vex_parser.detect_vex_format(file_path)
    
    def load_existing_vex(self, file_path: str) -> Dict[str, Any]:
        """Load an existing VEX document for editing using lib4vex."""
        return self.vex_parser.load_vex_document(file_path)
    
    def edit_vex_vulnerability(self, vex_document: Dict[str, Any], vuln_id: str, 
                             status: str, justification: Optional[str] = None, 
                             impact_statement: Optional[str] = None) -> Dict[str, Any]:
        """Edit vulnerability information in an existing VEX document using lib4vex."""
        return self.vex_parser.update_vex_vulnerability(vex_document, vuln_id, status, justification, impact_statement)
    
    # Legacy format-specific methods removed - now handled by lib4vex via vex_parser
    
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
    
    def save_vex_document(self, vex_data: Dict[str, Any], output_path: str) -> None:
        """Save the edited VEX document to a file using lib4vex."""
        self.vex_parser.save_vex_document(vex_data, output_path)
    
    def edit_existing_vex_file(self, input_file: str, vuln_id: str, status: str,
                             justification: Optional[str] = None, impact_statement: Optional[str] = None,
                             output_file: Optional[str] = None) -> str:
        """Edit an existing VEX file and return the updated content."""
        # Load existing VEX document using lib4vex
        vex_document = self.load_existing_vex(input_file)
        
        # Edit the vulnerability using lib4vex
        updated_data = self.edit_vex_vulnerability(vex_document, vuln_id, status, justification, impact_statement)
        
        # Determine output file
        if output_file is None:
            output_file = input_file  # Overwrite original file
        
        # Save the updated document using lib4vex
        self.save_vex_document(updated_data, output_file)
        
        # For backward compatibility, load the saved file and return its JSON content
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                saved_data = json.load(f)
            return json.dumps(saved_data, indent=2, ensure_ascii=False)
        except Exception:
            # Fallback: return the updated data structure as JSON
            return json.dumps(updated_data, indent=2, ensure_ascii=False)
