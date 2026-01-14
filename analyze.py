#!/usr/bin/env python3
import os
import json
import argparse
import logging
import subprocess
import hashlib
import time
from openai import OpenAI
from dotenv import load_dotenv
from typing import Dict, List, Any, Optional, Set
import fnmatch

# Import sensitive combinations
try:
    from permissions import very_sensitive_combinations, sensitive_combinations
except ImportError:
    logger.warning("permissions.py not found. Heuristic analysis will be disabled.")
    very_sensitive_combinations = []
    sensitive_combinations = []

# Load .env file if present
load_dotenv()

# Logging setup
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('analyze-agent')

class CloudSnapshotTools:
    """Internal tools for the AI to query the AWS assessment snapshot."""
    
    def __init__(self, results_dir: str, executor: Optional[Any] = None):
        self.results_dir = results_dir
        self.executor = executor
        self.evidence_dir = os.path.join(results_dir, 'evidence')
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)
        self._cache = {}

    def execute_command(self, command: str) -> str:
        """Execute a read-only AWS CLI command using the executor."""
        if not self.executor:
            return "Error: Active execution is disabled (no executor available)."
        return self.executor.execute(command)

    def _load_json(self, filename: str) -> Any:
        if filename in self._cache:
            return self._cache[filename]
        
        path = os.path.join(self.results_dir, filename)
        if not os.path.exists(path):
            return None
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                self._cache[filename] = data
                return data
        except Exception as e:
            logger.error(f"Error loading {path}: {e}")
            return None

    def get_caller_identity(self) -> Dict[str, Any]:
        """Get the sts:GetCallerIdentity result for the current session."""
        return self._load_json('caller_identity.json') or {}

    def list_principals(self, principal_type: str) -> List[str]:
        """List ARNs for a given principal type. principal_type: 'users' or 'roles'."""
        filename = 'iam_users.json' if principal_type == 'users' else 'iam_roles.json'
        data = self._load_json(filename)
        if not data: return []
        
        if principal_type == 'users':
            return [u['Arn'] for u in data if 'Arn' in u]
        else:
            return [r['RoleInfo']['Arn'] for r in data if 'RoleInfo' in r and 'Arn' in r['RoleInfo']]

    def get_principal_details(self, arn: str) -> Dict[str, Any]:
        """Get full details (policies, groups, etc.) for a specific User or Role ARN."""
        users_detailed = self._load_json('iam_users_detailed.json')
        if users_detailed:
            for user in users_detailed:
                if user.get('UserInfo', {}).get('Arn') == arn:
                    return user
        
        roles = self._load_json('iam_roles.json')
        if roles:
            for role in roles:
                if role.get('RoleInfo', {}).get('Arn') == arn:
                    return role
        
        return {"error": f"Principal {arn} not found in snapshot."}

    def get_policy_document(self, policy_arn: str, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Get the actual JSON document for an IAM policy ARN. If version_id is not provided, returns the default version."""
        policies = self._load_json('iam_policies.json')
        if policies:
            for p in policies:
                info = p.get('PolicyInfo', {})
                if info.get('Arn') == policy_arn:
                    if version_id:
                        for v in p.get('Versions', []):
                            if v.get('VersionId') == version_id:
                                return v.get('PolicyDocument', {})
                        return {"error": f"Version {version_id} not found for policy {policy_arn}"}
                    return p.get('PolicyDocument', {})
        return {"error": f"Policy {policy_arn} not found."}

    def list_available_policy_versions(self, policy_arn: str) -> List[Dict[str, Any]]:
        """List all available versions (VersionId, CreateDate, IsDefault) for a policy ARN."""
        policies = self._load_json('iam_policies.json')
        if policies:
            for p in policies:
                if p.get('PolicyInfo', {}).get('Arn') == policy_arn:
                    versions = []
                    for v in p.get('Versions', []):
                        versions.append({
                            "VersionId": v.get("VersionId"),
                            "CreateDate": v.get("CreateDate"),
                            "IsDefault": v.get("IsDefaultVersion")
                        })
                    return versions
        return []

    def get_infrastructure_summary(self) -> Dict[str, Any]:
        """Get a summary of EC2 instances, public IPs, and Lambda triggers."""
        return self._load_json('infrastructure_context.json') or {}

    def get_exposed_assets(self) -> Dict[str, Any]:
        """Get the audit results for exposed assets (S3, RDS, EC2, etc)."""
        return self._load_json('exposed_assets.json') or {}

    def get_resource_policies(self) -> Dict[str, Any]:
        """Get all discovered resource-based policies."""
        return self._load_json('resource_policies.json') or {}

    def list_iam_groups(self) -> List[str]:
        """List ARNs for all IAM groups in the account."""
        data = self._load_json('iam_groups.json')
        if not data: return []
        return [g['GroupInfo']['Arn'] for g in data if 'GroupInfo' in g and 'Arn' in g['GroupInfo']]

    def get_group_details(self, group_arn: str) -> Dict[str, Any]:
        """Get full details (attached policies, inline policies) for a specific IAM group ARN."""
        data = self._load_json('iam_groups.json')
        if data:
            for group in data:
                if group.get('GroupInfo', {}).get('Arn') == group_arn:
                    return group
        return {"error": f"Group {group_arn} not found in snapshot."}

    def list_evidence(self) -> List[str]:
        """List all gathered evidence files from active execution."""
        if not os.path.exists(self.evidence_dir):
            return []
        return os.listdir(self.evidence_dir)

    def read_evidence(self, filename: str) -> str:
        """Read the content of a specific evidence file."""
        path = os.path.join(self.evidence_dir, filename)
        if not os.path.exists(path):
            return f"Error: Evidence {filename} not found."
        try:
            with open(path, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error reading evidence: {e}"

    def get_all_heuristics(self) -> Dict[str, Any]:
        """Runs the heuristic scanner on all principals in the snapshot."""
        report = {"CRITICAL": [], "SENSITIVE": []}
        
        # Scan Users
        users = self._load_json('iam_users_detailed.json') or []
        for user in users:
            arn = user.get('UserInfo', {}).get('Arn', 'Unknown')
            findings = PermissionHeuristics.analyze_principal(user, self)
            for f in findings:
                report[f['severity']].append({"Arn": arn, "Type": "User", "Combo": f['combination']})
                
        # Scan Roles
        roles = self._load_json('iam_roles.json') or []
        for role in roles:
            arn = role.get('RoleInfo', {}).get('Arn', 'Unknown')
            findings = PermissionHeuristics.analyze_principal(role, self)
            for f in findings:
                report[f['severity']].append({"Arn": arn, "Type": "Role", "Combo": f['combination']})
                
        # Scan Groups
        groups = self._load_json('iam_groups.json') or []
        for group in groups:
            arn = group.get('GroupInfo', {}).get('Arn', 'Unknown')
            findings = PermissionHeuristics.analyze_principal(group, self)
            for f in findings:
                report[f['severity']].append({"Arn": arn, "Type": "Group", "Combo": f['combination']})
                
        return report

class PermissionHeuristics:
    """Matches IAM policy documents against known sensitive/risky permission combinations."""
    
    @staticmethod
    def action_matches(granted_action: str, target_action: str) -> bool:
        """Helper to match IAM actions, accounting for * wildcards."""
        # AWS actions are case-insensitive
        granted = granted_action.lower()
        target = target_action.lower()
        
        # Simple wildcard matching using fnmatch (standard globbing rules match IAM wildcards)
        return fnmatch.fnmatch(target, granted)

    @classmethod
    def check_combination(cls, granted_actions: Set[str], combination: List[str]) -> bool:
        """Returns True if EVERY action in the combination is granted."""
        for target in combination:
            found = False
            for granted in granted_actions:
                if cls.action_matches(granted, target):
                    found = True
                    break
            if not found:
                return False
        return True


    @classmethod
    def analyze_principal(cls, principal_data: Dict[str, Any], tools: 'CloudSnapshotTools') -> List[Dict[str, Any]]:
        """Scans a principal's policies for sensitive combinations."""
        findings = []
        
        # Collect all granted actions
        all_actions = set()
        
        # 1. Inline Policies
        for policy in principal_data.get('InlinePolicies', []):
            doc = policy.get('PolicyDocument', {})
            statements = doc.get('Statement', [])
            if isinstance(statements, dict): statements = [statements]
            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str): actions = [actions]
                    all_actions.update(actions)
        
        # 2. Attached Managed Policies
        for policy in principal_data.get('AttachedPolicies', []):
            # Prioritize locally embedded document if available
            doc = policy.get('PolicyDocument')
            if not doc:
                doc = tools.get_policy_document(policy.get('PolicyArn', ''))
            
            if not isinstance(doc, dict) or "Statement" not in doc:
                continue

            statements = doc.get('Statement', [])
            if isinstance(statements, dict): statements = [statements]
            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str): actions = [actions]
                    all_actions.update(actions)

        # Skip if no actions found
        if not all_actions:
            return []

        # Check very sensitive
        for combo in very_sensitive_combinations:
            if cls.check_combination(all_actions, combo):
                findings.append({"severity": "CRITICAL", "combination": combo})
        
        # Check sensitive
        for combo in sensitive_combinations:
            if cls.check_combination(all_actions, combo):
                findings.append({"severity": "SENSITIVE", "combination": combo})
        
        return findings

class ExecutionAgent:
    """Agent responsible for executing AWS CLI commands and saving output."""
    def __init__(self, profile: Optional[str], results_dir: str):
        self.profile = profile
        self.evidence_dir = os.path.join(results_dir, 'evidence')
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)

    def execute(self, command: str) -> str:
        """Execute an AWS CLI command and return the file path of the result."""
        # Safety & Redundancy filter: Only allow Read-Only/Discovery commands.
        # Blocking 'iam' and 'sts' because this data is already in the snapshot; use snapshot tools instead.
        blocked_keywords = [
            'delete', 'remove', 'terminate', 'stop', 'update', 'put-', 'create-', 'attach-', 'detach-', 'add-', 'modify-',
            'iam ', 'sts '
        ]
        if any(keyword in command.lower() for keyword in blocked_keywords):
            return "Error: Command blocked for safety or redundancy. For IAM/STS data, use the built-in snapshot tools instead of execute_command."

        full_cmd = command
        if self.profile:
            full_cmd += f" --profile {self.profile}"
        
        # Create a descriptive filename: aws_service_command_hash.json
        parts = command.split()
        # skip 'aws' if present
        start_idx = 1 if parts and parts[0] == 'aws' else 0
        desc = "_".join(parts[start_idx : start_idx + 2])
        # Sanitize
        desc = "".join(c if c.isalnum() or c == "_" else "-" for c in desc)
        
        cmd_id = hashlib.md5(full_cmd.encode()).hexdigest()[:6]
        filename = f"{desc}_{cmd_id}.json"
        out_path = os.path.join(self.evidence_dir, filename)

        logger.info(f"Executing: {full_cmd}")
        try:
            result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # Attempt to parse stdout as JSON for better formatting
            stdout_val = result.stdout
            try:
                if result.stdout.strip():
                    stdout_val = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass

            output = {
                "command": full_cmd,
                "stdout": stdout_val,
                "stderr": result.stderr,
                "exit_code": result.returncode
            }
            with open(out_path, 'w') as f:
                json.dump(output, f, indent=2)
            return filename
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return f"Error: {e}"

class DiscoveryAgent:
    """Identifies juicy resources for further investigation."""
    def __init__(self, client: OpenAI, tools: CloudSnapshotTools, model: str):
        self.client = client
        self.tools = tools
        self.model = model

    def discover_targets(self) -> List[str]:
        logger.info("Discovery Agent starting...")
        caller_basic = self.tools.get_caller_identity()
        caller_arn = caller_basic.get('Arn')
        caller_details = self.tools.get_principal_details(caller_arn) if caller_arn else caller_basic
        
        exposed = self.tools.get_exposed_assets()
        infra = self.tools.get_infrastructure_summary()
        heuristics = self.tools.get_all_heuristics()
        
        prompt = f"""
        Analyze this summary and list the AWS resources or IAM identities for a penetration tester to investigate further.
        Current Identity Details: {json.dumps(caller_details)}
        Heuristic Red Flags (Sensitive Permissions): {json.dumps(heuristics)}
        Exposed Assets: {json.dumps(exposed)}
        Infrastructure: {json.dumps(infra)}
        
        CRITICAL: Only include resources or identities that are EXPLICITLY mentioned in the summary above. Do NOT guess or list generic service names (like 'S3 buckets' or 'RDS instances') if they are not listed as discovered or exposed.
        If nothing interesting is found beyond the caller identity, just return a list containing the caller identity ARN.
        
        Return ONLY a JSON list of resource descriptions or ARNs, e.g., ["S3 bucket: secret-data", "arn:aws:iam::123456789012:user/target-user"].
        """
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        try:
            # Basic parsing, assume LLM returns a list
            content = response.choices[0].message.content
            # Remove markdown if present
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            
            logger.debug(f"Discovery Agent raw content: {content}")
            parsed = json.loads(content)
            logger.info(f"Discovery Agent identified targets: {parsed}")
            return parsed
        except Exception as e:
            logger.warning(f"Discovery Agent failed to parse JSON: {e}")
            logger.debug(f"Raw content was: {content}")
            caller_arn = caller.get('Arn')
            return [caller_arn] if caller_arn else []

class CommandAgent:
    """Tasks resources and crafts CLI commands."""
    def __init__(self, client: OpenAI, model: str):
        self.client = client
        self.model = model

    def craft_commands(self, targets: List[str]) -> List[str]:
        logger.info(f"Command Agent crafting commands for {len(targets)} targets...")
        prompt = f"""
        Generate a list of AWS CLI (v2) read-only commands (ls, describe, get-policy, etc.) to specifically enumerate these targets:
        {json.dumps(targets)}
        
        CRITICAL: Do NOT generate generic commands for services not mentioned in the target list. 
        PROHIBITED: Do NOT generate ANY 'iam' or 'sts' commands. Identity and policy data is already provided in the snapshot.
        CRITICAL: The snapshot ALREADY contains all IAM metadata. Do NOT generate any commands starting with 'aws iam' that fetch information about users, roles, groups, or policies (e.g., get-user, list-user-policies, get-role, list-attached-role-policies, get-policy, etc.). These are 100% redundant.
        
        Focus ONLY on:
        1. Non-IAM resources (S3, Lambda, Secrets Manager, etc.).
        2. Data-plane operations or detailed resource configurations (e.g., `aws lambda get-function`, `aws s3api list-objects`, `aws secretsmanager get-secret-value`).
        
        If a target is an IAM identity, do NOT generate IAM metadata commands for it. Instead, look for ways it interacts with other services mentioned in its policies.
        
        Return ONLY a JSON list of command strings.
        Example: ["aws s3api list-objects --bucket my-bucket", "aws lambda get-function --function-name my-func", "aws secretsmanager get-secret-value --secret-id my-secret"]
        """
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        try:
            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            
            logger.debug(f"Command Agent raw content: {content}")
            parsed = json.loads(content)
            logger.info(f"Command Agent crafted {len(parsed)} commands.")
            return parsed
        except Exception as e:
            logger.warning(f"Command Agent failed to parse JSON: {e}")
            logger.debug(f"Raw content was: {content}")
            return []

class AssessmentAnalyzer:
    def __init__(self, api_key: str, results_dir: str, profile: Optional[str], execute_active: bool, model_name: str = 'gpt-5.2'):
        self.api_key = api_key
        self.results_dir = results_dir
        self.profile = profile
        self.execute_active = execute_active
        self.model_name = model_name
        self.executor = ExecutionAgent(profile, results_dir)
        self.tools_provider = CloudSnapshotTools(results_dir, executor=self.executor if execute_active else None)
        self.client = OpenAI(api_key=self.api_key)

        self.tools = [
            {"type": "function", "function": {"name": "get_caller_identity", "description": "Get current identity.", "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "list_principals", "description": "List users/roles.", "parameters": {"type": "object", "properties": {"principal_type": {"type": "string", "enum": ["users", "roles"]}}, "required": ["principal_type"]}}},
            {"type": "function", "function": {"name": "get_principal_details", "description": "Get details for an ARN.", "parameters": {"type": "object", "properties": {"arn": {"type": "string"}}, "required": ["arn"]}}},
            {"type": "function", "function": {"name": "list_iam_groups", "description": "List ARNs for all IAM groups.", "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "get_group_details", "description": "Get details for an IAM group ARN.", "parameters": {"type": "object", "properties": {"group_arn": {"type": "string"}}, "required": ["group_arn"]}}},
            {"type": "function", "function": {"name": "get_policy_document", "description": "Get IAM policy JSON. Supports optional version_id.", "parameters": {"type": "object", "properties": {"policy_arn": {"type": "string"}, "version_id": {"type": "string"}}, "required": ["policy_arn"]}}},
            {"type": "function", "function": {"name": "list_available_policy_versions", "description": "List all versions for an IAM policy.", "parameters": {"type": "object", "properties": {"policy_arn": {"type": "string"}}, "required": ["policy_arn"]}}},
            {"type": "function", "function": {"name": "get_infrastructure_summary", "description": "Get EC2/Lambda summary.", "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "get_exposed_assets", "description": "Get audit of exposed assets.", "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "list_evidence", "description": "List execution results.", "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "read_evidence", "description": "Read specific evidence file.", "parameters": {"type": "object", "properties": {"filename": {"type": "string"}}, "required": ["filename"]}}},
            {"type": "function", "function": {"name": "get_all_heuristics", "description": "Run heuristic scan for sensitive permissions.", "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "execute_command", "description": "Execute a read-only AWS CLI command to gather more evidence.", "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
        ]

    def run_pipeline(self):
        if self.execute_active:
            # 1. Discovery
            discovery = DiscoveryAgent(self.client, self.tools_provider, self.model_name)
            targets = discovery.discover_targets()
            
            if not targets:
                logger.info("Discovery Agent found no specific targets. Skipping active enumeration.")
            else:
                # 2. Command Crafting
                commander = CommandAgent(self.client, self.model_name)
                commands = commander.craft_commands(targets)
                
                # 3. Execution (The Operator)
                logger.info(f"Execution Agent starting for {len(commands)} commands...")
                for cmd in commands:
                    self.executor.execute(cmd)
                    time.sleep(0.5)

        # 4. Final Analysis (The Expert)
        self.run_final_analysis()

    def run_final_analysis(self):
        logger.info(f"Final Analysis Agent starting using model: {self.model_name}")
        evidence_list = self.tools_provider.list_evidence()
        evidence_str = f"Extra evidence files available: {evidence_list}" if evidence_list else "No active evidence gathered."
        heuristics = self.tools_provider.get_all_heuristics()

        messages = [
            {"role": "system", "content": "You are a professional AWS Cloud Penetration Tester and Security Architect specializing in Identity and Access Management (IAM)."},
            {"role": "user", "content": f"""
MISSION: Identify any path to Privilege Escalation or Data Exfiltration.

HEURISTIC RED FLAGS (Identity Structural Risks):
{json.dumps(heuristics, indent=2)}

{evidence_str}

GUIDELINES:
1. Review the "Heuristic Red Flags" above—these identify principals with risky permission combinations.
2. Fetch caller identity and analyze permissions for the current user/role to see how they fit into the attack chain.
3. Investigate principals or roles flagged by heuristics using `get_principal_details`.
4. If `iam:PassRole` is granted, investigate which roles can be passed and what permissions those roles have.
5. If `sts:AssumeRole` is granted, investigate the trust policy and permissions of the target role(s) to find secondary escalation paths.
6. READ evidence files to understand the actual impact of discovered resources (e.g., secret values, function code).
7. SHADOW PERMISSIONS: Check for historical/non-default policy versions using `list_available_policy_versions`. Pentesting often reveals "backdoors" in older versions that can be reactivated via `iam:SetDefaultPolicyVersion`.
8. PROHIBITED: Do NOT use `execute_command` for any `iam` or `sts` commands. All identity data MUST be fetched via `get_principal_details` or `get_policy_document` to avoid redundant scanning.
9. Present findings in a professional MARKDOWN report with a "Critical Findings" section at the top.
"""}
        ]
        
        try:
            while True:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    tools=self.tools,
                    tool_choice="auto",
                )
                
                resp_msg = response.choices[0].message
                messages.append(resp_msg)
                
                if not resp_msg.tool_calls:
                    break
                
                for tool_call in resp_msg.tool_calls:
                    f_name = tool_call.function.name
                    f_args_raw = tool_call.function.arguments
                    logger.debug(f"Tool call arguments (raw): {f_args_raw}")
                    try:
                        f_args = json.loads(f_args_raw)
                    except Exception as e:
                        logger.error(f"Failed to parse tool arguments for {f_name}: {e}")
                        continue
                        
                    logger.info(f"Analyzing Evidence/Data: {f_name}({f_args})")
                    f_to_call = getattr(self.tools_provider, f_name)
                    f_resp = f_to_call(**f_args)
                    messages.append({"tool_call_id": tool_call.id, "role": "tool", "name": f_name, "content": json.dumps(f_resp)})
            
            final_content = resp_msg.content
            report_path = os.path.join(self.results_dir, 'escalation_report.md')
            with open(report_path, 'w') as f:
                f.write(final_content)
            
            logger.info(f"Analysis complete! Report saved to: {report_path}")
            print("\n--- ANALYSIS SUMMARY ---")
            print('\n'.join(final_content.split('\n')[:20]))
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")

def main():
    parser = argparse.ArgumentParser(description='Multi-Agent AWS Escalation Analyzer')
    parser.add_argument('--input', required=True, help='Directory containing IAMenum JSON results')
    parser.add_argument('--api-key', help='OpenAI API Key')
    parser.add_argument('--model', default='gpt-5.2', help='OpenAI model')
    parser.add_argument('--profile', help='AWS Profile for active execution')
    parser.add_argument('--execute', action='store_true', help='Enable active enumeration (Discovery -> Execution)')
    parser.add_argument('--debug', action='store_true', help='Enable verbose debug logging')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        for handler in logging.root.handlers:
            handler.setLevel(logging.DEBUG)

    api_key = args.api_key or os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print("Error: OpenAI API Key required.")
        return

    analyzer = AssessmentAnalyzer(api_key, args.input, args.profile, args.execute, args.model)
    analyzer.run_pipeline()

if __name__ == '__main__':
    main()
