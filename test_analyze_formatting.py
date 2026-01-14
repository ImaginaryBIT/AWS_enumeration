import unittest
import json
import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch
from analyze import ExecutionAgent

class TestExecutionFormatting(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for results
        self.test_dir = tempfile.mkdtemp()
        self.evidence_dir = os.path.join(self.test_dir, 'evidence')
        # ExecutionAgent creates evidence dir in __init__
        self.agent = ExecutionAgent(profile="test-profile", results_dir=self.test_dir)

    def tearDown(self):
        # Clean up the temporary directory
        shutil.rmtree(self.test_dir)

    @patch('subprocess.run')
    def test_json_formatting(self, mock_run):
        # Mock a successful AWS CLI command returning JSON
        mock_stdout = '{"key": "value", "list": [1, 2, 3]}'
        mock_run.return_value = MagicMock(
            stdout=mock_stdout,
            stderr="",
            returncode=0
        )

        command = "aws s3api list-buckets"
        filename = self.agent.execute(command)
        
        # Verify the descriptive filename was used
        self.assertTrue(filename.startswith("s3api_list-buckets_"))
        
        # Verify the file was created
        file_path = os.path.join(self.evidence_dir, filename)
        self.assertTrue(os.path.exists(file_path))

        # Verify the content is correctly formatted JSON
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        # The 'stdout' key should now contain a DICT, not a STRING
        self.assertIsInstance(data['stdout'], dict)
        self.assertEqual(data['stdout']['key'], "value")
        self.assertEqual(data['stdout']['list'], [1, 2, 3])
        
        # Verify it's pretty-printed in the file (indent=2)
        with open(file_path, 'r') as f:
            raw_content = f.read()
            # Check for characteristic indentation
            self.assertIn('  "key": "value"', raw_content)

    @patch('subprocess.run')
    def test_non_json_output(self, mock_run):
        # Mock a successful command returning plain text
        mock_stdout = 'Success: Operation completed'
        mock_run.return_value = MagicMock(
            stdout=mock_stdout,
            stderr="",
            returncode=0
        )

        command = "aws s3 cp file1 s3://bucket/"
        filename = self.agent.execute(command)
        
        # Verify the descriptive filename was used
        self.assertTrue(filename.startswith("s3_cp_"))
        
        file_path = os.path.join(self.evidence_dir, filename)
        self.assertTrue(os.path.exists(file_path))
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        # The 'stdout' key should remain a STRING
        self.assertIsInstance(data['stdout'], str)
        self.assertEqual(data['stdout'], mock_stdout)

if __name__ == '__main__':
    unittest.main()
