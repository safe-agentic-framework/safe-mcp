#!/usr/bin/env python3
"""
SAFE-MCP Markdown Parser
Parses markdown technique and mitigation files into structured JSON format.
"""

import json
import os
import re
import yaml
from datetime import datetime, timezone, date
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime and date objects."""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


class MarkdownParser:
    """Base parser for markdown files."""

    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)

    @staticmethod
    def extract_section(content: str, heading: str, level: int = 2) -> Optional[str]:
        """Extract content under a specific heading."""
        heading_marker = '#' * level
        pattern = rf'^{heading_marker}\s+{re.escape(heading)}$(.*?)(?=^#{{{1,{level}}}}\s|\Z)'
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
        return match.group(1).strip() if match else None

    @staticmethod
    def extract_paragraphs(content: str) -> List[str]:
        """Extract paragraphs from text content."""
        paragraphs = []
        for para in content.split('\n\n'):
            para = para.strip()
            if para and not para.startswith('#') and not para.startswith('```'):
                # Remove markdown formatting but keep the text
                para = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', para)  # Remove links
                para = re.sub(r'\*\*([^\*]+)\*\*', r'\1', para)  # Remove bold
                para = re.sub(r'\*([^\*]+)\*', r'\1', para)  # Remove italic
                paragraphs.append(para)
        return paragraphs

    @staticmethod
    def extract_list_items(content: str) -> List[str]:
        """Extract list items from markdown."""
        items = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('-') or line.startswith('*'):
                item = re.sub(r'^[-*]\s+', '', line)
                # Remove markdown formatting
                item = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', item)
                item = re.sub(r'\*\*([^\*]+)\*\*', r'\1', item)
                items.append(item.strip())
        return items

    @staticmethod
    def parse_overview_field(content: str, field_name: str) -> Optional[str]:
        """Parse a field from the Overview section."""
        pattern = rf'^\*\*{re.escape(field_name)}\*\*:\s*(.+)$'
        match = re.search(pattern, content, re.MULTILINE)
        return match.group(1).strip() if match else None

    @staticmethod
    def parse_table(content: str) -> List[Dict[str, str]]:
        """Parse markdown table into list of dictionaries."""
        lines = [l.strip() for l in content.split('\n') if l.strip() and '|' in l]
        if len(lines) < 3:  # Need header, separator, and at least one row
            return []

        # Parse header - normalize to lowercase with underscores
        headers = [h.strip().lower().replace(' ', '_') for h in lines[0].split('|')[1:-1]]

        # Parse rows (skip separator line)
        rows = []
        for line in lines[2:]:
            values = [v.strip() for v in line.split('|')[1:-1]]
            if len(values) == len(headers):
                rows.append(dict(zip(headers, values)))

        return rows


class TechniqueParser(MarkdownParser):
    """Parser for SAFE-MCP technique markdown files."""

    def parse_technique(self, file_path: Path) -> Dict[str, Any]:
        """Parse a technique markdown file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        technique = {}

        # Extract ID and name from title
        title_match = re.search(r'^#\s+SAFE-T([0-9]{4}(?:\.[0-9]{3})?):(.+)$', content, re.MULTILINE)
        if title_match:
            technique['id'] = f"SAFE-T{title_match.group(1)}"
            technique['name'] = title_match.group(2).strip()

        # Parse Overview section
        overview = self.extract_section(content, 'Overview')
        if overview:
            tactic_str = self.parse_overview_field(overview, 'Tactic')
            if tactic_str:
                tactic_match = re.search(r'(.+?)\s*\(([^)]+)\)', tactic_str)
                if tactic_match:
                    technique['tactic'] = {
                        'name': tactic_match.group(1).strip(),
                        'id': tactic_match.group(2).strip()
                    }

            technique['severity'] = self.parse_overview_field(overview, 'Severity')
            technique['first_observed'] = self.parse_overview_field(overview, 'First Observed')
            technique['last_updated'] = self.parse_overview_field(overview, 'Last Updated')

        # Parse Description
        desc_section = self.extract_section(content, 'Description')
        if desc_section:
            technique['description'] = self.extract_paragraphs(desc_section)

        # Parse Attack Vectors
        attack_vectors_section = self.extract_section(content, 'Attack Vectors')
        if attack_vectors_section:
            attack_vectors = {}
            primary = self.parse_overview_field(attack_vectors_section, 'Primary Vector')
            if primary:
                attack_vectors['primary'] = primary

            secondary_match = re.search(r'\*\*Secondary Vectors\*\*:(.*?)(?=\n\n|\Z)', attack_vectors_section, re.DOTALL)
            if secondary_match:
                attack_vectors['secondary'] = self.extract_list_items(secondary_match.group(1))

            if attack_vectors:
                technique['attack_vectors'] = attack_vectors

        # Parse Technical Details
        tech_details = self.parse_technical_details(content)
        if tech_details:
            technique['technical_details'] = tech_details

        # Parse Impact Assessment
        impact = self.parse_impact_assessment(content)
        if impact:
            technique['impact_assessment'] = impact

        # Parse Detection Methods
        detection = self.parse_detection_methods(content, file_path)
        if detection:
            technique['detection_methods'] = detection

        # Parse Mitigation Strategies
        mitigations = self.parse_mitigation_strategies(content)
        if mitigations:
            technique['mitigation_strategies'] = mitigations

        # Parse Related Techniques
        related = self.parse_related_techniques(content)
        if related:
            technique['related_techniques'] = related

        # Parse Sub-Techniques
        sub_techniques = self.parse_sub_techniques(content)
        if sub_techniques:
            technique['sub_techniques'] = sub_techniques

        # Parse Real-World Incidents
        incidents = self.parse_real_world_incidents(content)
        if incidents:
            technique['real_world_incidents'] = incidents

        # Parse References
        references = self.parse_references(content)
        if references:
            technique['references'] = references

        # Parse MITRE ATT&CK Mapping
        mitre = self.parse_mitre_mapping(content)
        if mitre:
            technique['mitre_attack_mapping'] = mitre

        # Parse Version History
        version_history = self.parse_version_history(content)
        if version_history:
            technique['version_history'] = version_history

        # Add test files if they exist
        test_files = self.find_test_files(file_path)
        if test_files:
            technique['test_files'] = test_files

        # Add metadata
        technique['metadata'] = {
            'file_path': str(file_path.relative_to(self.root_dir)),
            'last_parsed': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }

        return technique

    def parse_technical_details(self, content: str) -> Dict[str, Any]:
        """Parse Technical Details section."""
        tech_details = {}

        # Prerequisites
        prereq_section = self.extract_section(content, 'Prerequisites', level=3)
        if prereq_section:
            tech_details['prerequisites'] = self.extract_list_items(prereq_section)

        # Attack Flow
        flow_section = self.extract_section(content, 'Attack Flow', level=3)
        if flow_section:
            attack_flow = []
            # Extract numbered items
            for match in re.finditer(r'^\d+\.\s+\*\*([^*]+)\*\*:\s*(.+)$', flow_section, re.MULTILINE):
                attack_flow.append({
                    'stage': match.group(1).strip(),
                    'description': match.group(2).strip()
                })
            if attack_flow:
                tech_details['attack_flow'] = attack_flow

        # Example Scenario
        example_section = self.extract_section(content, 'Example Scenario', level=3)
        if example_section:
            code_match = re.search(r'```(\w+)?\n(.*?)```', example_section, re.DOTALL)
            if code_match:
                tech_details['example_scenario'] = {
                    'language': code_match.group(1) or 'text',
                    'code': code_match.group(2).strip()
                }

        return tech_details

    def parse_impact_assessment(self, content: str) -> Dict[str, Any]:
        """Parse Impact Assessment section."""
        impact_section = self.extract_section(content, 'Impact Assessment')
        if not impact_section:
            return {}

        impact = {}

        for category in ['Confidentiality', 'Integrity', 'Availability', 'Scope']:
            pattern = rf'\*\*{category}\*\*:\s*([^-]+)\s*-\s*(.+?)(?=\n\*\*|\n\n|\Z)'
            match = re.search(pattern, impact_section, re.DOTALL)
            if match:
                impact[category.lower()] = {
                    'level': match.group(1).strip(),
                    'description': match.group(2).strip()
                }

        return impact

    def parse_detection_methods(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Parse Detection Methods section."""
        detection = {}

        # IoCs
        ioc_section = self.extract_section(content, 'Indicators of Compromise \\(IoCs\\)', level=3)
        if ioc_section:
            detection['indicators_of_compromise'] = self.extract_list_items(ioc_section)

        # Behavioral Indicators
        behavioral_section = self.extract_section(content, 'Behavioral Indicators', level=3)
        if behavioral_section:
            detection['behavioral_indicators'] = self.extract_list_items(behavioral_section)

        # Check for Sigma rule file
        rule_file = file_path.parent / 'detection-rule.yml'
        if not rule_file.exists():
            rule_file = file_path.parent / 'detection-rule.yaml'

        if rule_file.exists():
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    sigma_rule = yaml.safe_load(f)
                    sigma_rule['file_path'] = str(rule_file.relative_to(self.root_dir))
                    detection['sigma_rules'] = [sigma_rule]
            except Exception as e:
                print(f"Warning: Could not parse {rule_file}: {e}")

        return detection

    def parse_mitigation_strategies(self, content: str) -> Dict[str, Any]:
        """Parse Mitigation Strategies section."""
        mitigations = {}

        # Preventive Controls
        preventive_section = self.extract_section(content, 'Preventive Controls', level=3)
        if preventive_section:
            preventive = []
            for match in re.finditer(r'\*\*\[?(SAFE-M-\d+):?\s*([^\]]+)\]?\*\*:?\s*(.+?)(?=\n\d+\.|\Z)', preventive_section, re.DOTALL):
                preventive.append({
                    'id': match.group(1).strip(),
                    'name': match.group(2).strip(),
                    'description': match.group(3).strip()
                })
            if preventive:
                mitigations['preventive_controls'] = preventive

        # Detective Controls
        detective_section = self.extract_section(content, 'Detective Controls', level=3)
        if detective_section:
            detective = []
            for match in re.finditer(r'\*\*\[?(SAFE-M-\d+):?\s*([^\]]+)\]?\*\*:?\s*(.+?)(?=\n\d+\.|\Z)', detective_section, re.DOTALL):
                detective.append({
                    'id': match.group(1).strip(),
                    'name': match.group(2).strip(),
                    'description': match.group(3).strip()
                })
            if detective:
                mitigations['detective_controls'] = detective

        # Response Procedures
        response_section = self.extract_section(content, 'Response Procedures', level=3)
        if response_section:
            response = {}

            for subsection in ['Immediate Actions', 'Investigation Steps', 'Remediation']:
                subsec_content = self.extract_section(response_section, subsection, level=4)
                if not subsec_content:
                    # Try numbered format
                    pattern = rf'\d+\.\s+\*\*{subsection}\*\*:(.*?)(?=\n\d+\.|\Z)'
                    match = re.search(pattern, response_section, re.DOTALL)
                    if match:
                        subsec_content = match.group(1)

                if subsec_content:
                    key = subsection.lower().replace(' ', '_')
                    response[key] = self.extract_list_items(subsec_content)

            if response:
                mitigations['response_procedures'] = response

        return mitigations

    def parse_related_techniques(self, content: str) -> List[Dict[str, str]]:
        """Parse Related Techniques section."""
        related_section = self.extract_section(content, 'Related Techniques')
        if not related_section:
            return []

        related = []
        # Match format: - [SAFE-TXXXX](link): Description OR - SAFE-TXXXX: Description
        for match in re.finditer(r'-\s*\[?(SAFE-T\d{4}(?:\.\d{3})?)\]?\([^\)]+\)?:\s*(.+?)(?=\n-|\Z)', related_section, re.DOTALL):
            tech_id = match.group(1).strip()
            relationship = match.group(2).strip()

            # Try to extract name from the link text if available
            name_match = re.search(rf'\[{re.escape(tech_id)}\]\([^\)]+\):\s*([^-]+)', match.group(0))
            name = name_match.group(1).strip() if name_match else relationship.split(' - ')[0].strip() if ' - ' in relationship else ''

            related.append({
                'id': tech_id,
                'name': name if name and name != relationship else '',
                'relationship': relationship
            })

        return related

    def parse_sub_techniques(self, content: str) -> List[Dict[str, Any]]:
        """Parse Sub-Techniques section."""
        sub_tech_section = self.extract_section(content, 'Sub-Techniques')
        if not sub_tech_section:
            return []

        sub_techniques = []
        # Match sub-technique headings
        for match in re.finditer(r'###\s+(SAFE-T\d{4}\.\d{3}):\s*(.+?)\n(.*?)(?=###|##|\Z)', sub_tech_section, re.DOTALL):
            sub_tech = {
                'id': match.group(1).strip(),
                'name': match.group(2).strip(),
                'description': match.group(3).strip()
            }
            # Extract list items from description
            details = self.extract_list_items(match.group(3))
            if details:
                sub_tech['details'] = details
            sub_techniques.append(sub_tech)

        return sub_techniques

    def parse_real_world_incidents(self, content: str) -> List[Dict[str, Any]]:
        """Parse Real-World Incidents section."""
        incidents_section = self.extract_section(content, 'Real-World Incidents')
        if not incidents_section:
            return []

        incidents = []
        # Match incident subsections
        for match in re.finditer(r'###\s+(.+?)\(([^)]+)\)\n(.*?)(?=###|##|\Z)', incidents_section, re.DOTALL):
            incident = {
                'title': match.group(1).strip(),
                'date': match.group(2).strip(),
                'description': match.group(3).strip()
            }

            # Extract CVE if present
            cve_match = re.search(r'CVE-\d{4}-\d+', match.group(3))
            if cve_match:
                incident['cve'] = cve_match.group(0)

            incidents.append(incident)

        return incidents

    def parse_references(self, content: str) -> List[Dict[str, str]]:
        """Parse References section."""
        ref_section = self.extract_section(content, 'References')
        if not ref_section:
            return []

        references = []
        # Match markdown links
        for match in re.finditer(r'-\s*\[([^\]]+)\]\(([^\)]+)\)', ref_section):
            references.append({
                'title': match.group(1).strip(),
                'url': match.group(2).strip()
            })

        return references

    def parse_mitre_mapping(self, content: str) -> List[Dict[str, str]]:
        """Parse MITRE ATT&CK Mapping section."""
        mitre_section = self.extract_section(content, 'MITRE ATT&CK Mapping')
        if not mitre_section:
            return []

        mappings = []
        for match in re.finditer(r'-\s*\[([T\d.]+)\s*-\s*([^\]]+)\]\(([^\)]+)\)', mitre_section):
            mappings.append({
                'id': match.group(1).strip(),
                'name': match.group(2).strip(),
                'url': match.group(3).strip()
            })

        return mappings

    def parse_version_history(self, content: str) -> List[Dict[str, str]]:
        """Parse Version History table."""
        history_section = self.extract_section(content, 'Version History')
        if not history_section:
            return []

        return self.parse_table(history_section)

    def find_test_files(self, markdown_path: Path) -> Dict[str, str]:
        """Find test files associated with a technique."""
        test_files = {}

        # Detection rule
        for ext in ['.yml', '.yaml']:
            rule_file = markdown_path.parent / f'detection-rule{ext}'
            if rule_file.exists():
                test_files['detection_rule'] = str(rule_file.relative_to(self.root_dir))
                break

        # Test logs
        logs_file = markdown_path.parent / 'test-logs.json'
        if logs_file.exists():
            test_files['test_logs'] = str(logs_file.relative_to(self.root_dir))

        # Test script
        test_script = markdown_path.parent / 'test_detection_rule.py'
        if test_script.exists():
            test_files['test_script'] = str(test_script.relative_to(self.root_dir))

        return test_files


class MitigationParser(MarkdownParser):
    """Parser for SAFE-MCP mitigation markdown files."""

    def parse_mitigation(self, file_path: Path) -> Dict[str, Any]:
        """Parse a mitigation markdown file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        mitigation = {}

        # Extract ID and name from title
        title_match = re.search(r'^#\s+SAFE-M-(\d+):(.+)$', content, re.MULTILINE)
        if title_match:
            mitigation['id'] = f"SAFE-M-{title_match.group(1)}"
            # Name may contain category
            name_parts = title_match.group(2).strip().split(' - ', 1)
            if len(name_parts) == 2:
                mitigation['name'] = name_parts[1].strip()
            else:
                mitigation['name'] = name_parts[0].strip()

        # Parse Overview section
        overview = self.extract_section(content, 'Overview')
        if overview:
            mitigation['category'] = self.parse_overview_field(overview, 'Category')

            effectiveness_str = self.parse_overview_field(overview, 'Effectiveness')
            if effectiveness_str:
                # Parse effectiveness with optional additional context
                eff_match = re.search(r'([^(]+)(?:\(([^)]+)\))?', effectiveness_str)
                if eff_match:
                    mitigation['effectiveness'] = {
                        'level': eff_match.group(1).strip()
                    }
                    if eff_match.group(2):
                        mitigation['effectiveness']['additional_context'] = eff_match.group(2).strip()

            mitigation['implementation_complexity'] = self.parse_overview_field(overview, 'Implementation Complexity')
            mitigation['first_published'] = self.parse_overview_field(overview, 'First Published')

        # Parse Description
        desc_section = self.extract_section(content, 'Description')
        if desc_section:
            mitigation['description'] = self.extract_paragraphs(desc_section)

        # Parse Mitigates section
        mitigates_section = self.extract_section(content, 'Mitigates')
        if mitigates_section:
            mitigates = []
            for match in re.finditer(r'\[?(SAFE-T\d{4}(?:\.\d{3})?)\]?.*?:\s*(.+?)(?=\n-|\Z)', mitigates_section, re.DOTALL):
                mitigates.append({
                    'id': match.group(1).strip(),
                    'name': match.group(2).strip()
                })
            if mitigates:
                mitigation['mitigates'] = mitigates

        # Parse Technical Implementation
        tech_impl = self.parse_technical_implementation(content)
        if tech_impl:
            mitigation['technical_implementation'] = tech_impl

        # Parse Benefits
        benefits_section = self.extract_section(content, 'Benefits')
        if benefits_section:
            benefits = []
            for match in re.finditer(r'\*\*([^*]+)\*\*:\s*(.+?)(?=\n-|\n\n|\Z)', benefits_section, re.DOTALL):
                benefits.append({
                    'name': match.group(1).strip(),
                    'description': match.group(2).strip()
                })
            if benefits:
                mitigation['benefits'] = benefits

        # Parse Limitations
        limitations_section = self.extract_section(content, 'Limitations')
        if limitations_section:
            limitations = []
            for match in re.finditer(r'\*\*([^*]+)\*\*:\s*(.+?)(?=\n-|\n\n|\Z)', limitations_section, re.DOTALL):
                limitations.append({
                    'name': match.group(1).strip(),
                    'description': match.group(2).strip()
                })
            if limitations:
                mitigation['limitations'] = limitations

        # Parse Implementation Examples
        examples = self.parse_implementation_examples(content)
        if examples:
            mitigation['implementation_examples'] = examples

        # Parse Testing and Validation
        testing = self.parse_testing_validation(content)
        if testing:
            mitigation['testing_and_validation'] = testing

        # Parse Deployment Considerations
        deployment = self.parse_deployment_considerations(content)
        if deployment:
            mitigation['deployment_considerations'] = deployment

        # Parse References
        references = self.parse_references(content)
        if references:
            mitigation['references'] = references

        # Parse Related Mitigations
        related = self.parse_related_mitigations(content)
        if related:
            mitigation['related_mitigations'] = related

        # Parse Version History
        version_history = self.parse_version_history(content)
        if version_history:
            mitigation['version_history'] = version_history

        # Add metadata
        mitigation['metadata'] = {
            'file_path': str(file_path.relative_to(self.root_dir)),
            'last_parsed': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }

        return mitigation

    def parse_technical_implementation(self, content: str) -> Dict[str, Any]:
        """Parse Technical Implementation section."""
        impl = {}

        # Core Principles
        principles_section = self.extract_section(content, 'Core Principles', level=3)
        if principles_section:
            principles = []
            for match in re.finditer(r'\d+\.\s+\*\*([^*]+)\*\*:\s*(.+?)(?=\n\d+\.|\Z)', principles_section, re.DOTALL):
                principles.append({
                    'name': match.group(1).strip(),
                    'description': match.group(2).strip()
                })
            if principles:
                impl['core_principles'] = principles

        # Prerequisites
        prereq_section = self.extract_section(content, 'Prerequisites', level=3)
        if prereq_section:
            impl['prerequisites'] = self.extract_list_items(prereq_section)

        # Implementation Steps
        steps_section = self.extract_section(content, 'Implementation Steps', level=3)
        if steps_section:
            steps = []
            for match in re.finditer(r'\d+\.\s+\*\*([^*]+)\*\*:(.*?)(?=\n\d+\.|\Z)', steps_section, re.DOTALL):
                phase_steps = self.extract_list_items(match.group(2))
                steps.append({
                    'phase': match.group(1).strip(),
                    'steps': phase_steps
                })
            if steps:
                impl['implementation_steps'] = steps

        return impl

    def parse_implementation_examples(self, content: str) -> List[Dict[str, str]]:
        """Parse Implementation Examples section."""
        examples_section = self.extract_section(content, 'Implementation Examples')
        if not examples_section:
            return []

        examples = []
        for match in re.finditer(r'###\s+Example\s+\d+:\s*(.+?)\n```(\w+)?\n(.*?)```', examples_section, re.DOTALL):
            examples.append({
                'title': match.group(1).strip(),
                'language': match.group(2) or 'text',
                'code': match.group(3).strip()
            })

        return examples

    def parse_testing_validation(self, content: str) -> Dict[str, List[str]]:
        """Parse Testing and Validation section."""
        testing_section = self.extract_section(content, 'Testing and Validation')
        if not testing_section:
            return {}

        testing = {}

        for test_type in ['Security Testing', 'Functional Testing', 'Integration Testing']:
            type_section = self.extract_section(testing_section, test_type, level=4)
            if not type_section:
                # Try numbered format
                pattern = rf'\d+\.\s+\*\*{test_type}\*\*:(.*?)(?=\n\d+\.|\Z)'
                match = re.search(pattern, testing_section, re.DOTALL)
                if match:
                    type_section = match.group(1)

            if type_section:
                key = test_type.lower().replace(' ', '_')
                testing[key] = self.extract_list_items(type_section)

        return testing

    def parse_deployment_considerations(self, content: str) -> Dict[str, Any]:
        """Parse Deployment Considerations section."""
        deploy_section = self.extract_section(content, 'Deployment Considerations')
        if not deploy_section:
            return {}

        deployment = {}

        # Resource Requirements
        resource_section = self.extract_section(deploy_section, 'Resource Requirements', level=3)
        if resource_section:
            resources = {}
            for resource_type in ['CPU', 'Memory', 'Storage', 'Network']:
                pattern = rf'\*\*{resource_type}\*\*:\s*(.+?)(?=\n\*\*|\Z)'
                match = re.search(pattern, resource_section, re.DOTALL)
                if match:
                    resources[resource_type.lower()] = match.group(1).strip()
            if resources:
                deployment['resource_requirements'] = resources

        # Performance Impact
        perf_section = self.extract_section(deploy_section, 'Performance Impact', level=3)
        if perf_section:
            performance = {}
            for perf_type in ['Latency', 'Throughput', 'Resource Usage']:
                pattern = rf'\*\*{perf_type}\*\*:\s*(.+?)(?=\n\*\*|\Z)'
                match = re.search(pattern, perf_section, re.DOTALL)
                if match:
                    performance[perf_type.lower().replace(' ', '_')] = match.group(1).strip()
            if performance:
                deployment['performance_impact'] = performance

        # Monitoring and Alerting
        monitoring_section = self.extract_section(deploy_section, 'Monitoring and Alerting', level=3)
        if monitoring_section:
            deployment['monitoring_and_alerting'] = self.extract_list_items(monitoring_section)

        return deployment

    def parse_references(self, content: str) -> List[Dict[str, str]]:
        """Parse References section."""
        ref_section = self.extract_section(content, 'References')
        if not ref_section:
            return []

        references = []
        for match in re.finditer(r'-\s*\[([^\]]+)\]\(([^\)]+)\)', ref_section):
            references.append({
                'title': match.group(1).strip(),
                'url': match.group(2).strip()
            })

        return references

    def parse_related_mitigations(self, content: str) -> List[Dict[str, str]]:
        """Parse Related Mitigations section."""
        related_section = self.extract_section(content, 'Related Mitigations')
        if not related_section:
            return []

        related = []
        for match in re.finditer(r'\[?(SAFE-M-\d+)\]?.*?:\s*(.+?)(?=\n-|\Z)', related_section, re.DOTALL):
            related.append({
                'id': match.group(1).strip(),
                'relationship': match.group(2).strip()
            })

        return related

    def parse_version_history(self, content: str) -> List[Dict[str, str]]:
        """Parse Version History table."""
        history_section = self.extract_section(content, 'Version History')
        if not history_section:
            return []

        return self.parse_table(history_section)


def parse_all_techniques(root_dir: str) -> List[Dict[str, Any]]:
    """Parse all technique markdown files."""
    parser = TechniqueParser(root_dir)
    techniques_dir = Path(root_dir) / 'techniques'
    techniques = []

    for tech_dir in sorted(techniques_dir.iterdir()):
        if tech_dir.is_dir() and tech_dir.name.startswith('SAFE-T'):
            readme = tech_dir / 'README.md'
            if readme.exists():
                try:
                    technique = parser.parse_technique(readme)
                    techniques.append(technique)
                    print(f"Parsed: {technique.get('id', tech_dir.name)}")
                except Exception as e:
                    print(f"Error parsing {readme}: {e}")

    return techniques


def parse_all_mitigations(root_dir: str) -> List[Dict[str, Any]]:
    """Parse all mitigation markdown files."""
    parser = MitigationParser(root_dir)
    mitigations_dir = Path(root_dir) / 'mitigations'
    mitigations = []

    for mit_dir in sorted(mitigations_dir.iterdir()):
        if mit_dir.is_dir() and mit_dir.name.startswith('SAFE-M'):
            readme = mit_dir / 'README.md'
            if readme.exists():
                try:
                    mitigation = parser.parse_mitigation(readme)
                    mitigations.append(mitigation)
                    print(f"Parsed: {mitigation.get('id', mit_dir.name)}")
                except Exception as e:
                    print(f"Error parsing {readme}: {e}")

    return mitigations


def extract_tactics_from_readme(root_dir: str) -> List[Dict[str, Any]]:
    """Extract tactics from the main README.md."""
    readme_path = Path(root_dir) / 'README.md'

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find the tactics table
    tactics_match = re.search(r'## SAFE-MCP Tactics.*?\n\n(.*?)(?=\n##)', content, re.DOTALL)
    if not tactics_match:
        return []

    tactics_content = tactics_match.group(1)

    # Parse the table
    lines = [l.strip() for l in tactics_content.split('\n') if l.strip() and '|' in l]
    tactics = []

    for line in lines[2:]:  # Skip header and separator
        parts = [p.strip() for p in line.split('|')[1:-1]]
        if len(parts) >= 3:
            tactics.append({
                'id': parts[0],
                'name': parts[1],
                'description': parts[2]
            })

    return tactics


def main():
    parser = argparse.ArgumentParser(description='Parse SAFE-MCP markdown files to JSON')
    parser.add_argument('--root-dir', default='.', help='Root directory of SAFE-MCP repository')
    parser.add_argument('--output', default='data/safe-mcp-index.json', help='Output JSON file')
    args = parser.parse_args()

    root_dir = Path(args.root_dir).resolve()

    print("Parsing tactics...")
    tactics = extract_tactics_from_readme(root_dir)

    print("\nParsing techniques...")
    techniques = parse_all_techniques(root_dir)

    print("\nParsing mitigations...")
    mitigations = parse_all_mitigations(root_dir)

    # Combine into index
    index = {
        'metadata': {
            'version': '1.0',
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'generator': 'SAFE-MCP Markdown Parser',
            'total_tactics': len(tactics),
            'total_techniques': len(techniques),
            'total_mitigations': len(mitigations)
        },
        'tactics': tactics,
        'techniques': techniques,
        'mitigations': mitigations
    }

    # Write output
    output_path = Path(root_dir) / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

    print(f"\n✓ Generated {output_path}")
    print(f"  - {len(tactics)} tactics")
    print(f"  - {len(techniques)} techniques")
    print(f"  - {len(mitigations)} mitigations")


if __name__ == '__main__':
    main()
