import unittest
from unittest.mock import patch
from src.data_analysis import count_severities_distribution, count_cves_per_product
from src.data_fetch import CPENotation, get_description, get_base_severity, search_by_software_cpe
from src.report import generate_report
from src.utils import clean_system

class TestCVEAnalysis(unittest.TestCase):

    def setUp(self):
        """

        """
        # Mocking the response from the API
        self.mock_response = {
            'vulnerabilities': [
                {
                    'CVE': 'CVE-2022-1234',
                    'cve': {
                        'descriptions': [{'lang': 'en', 'value': 'A sample CVE description'}],
                        'metrics': {'cvssMetricV2': [{'baseSeverity': 'LOW'}]}
                    }
                },
                {
                    'CVE': 'CVE-2022-5678',
                    'cve': {
                        'descriptions': [{'lang': 'en', 'value': 'Another sample CVE description'}],
                        'metrics': {'cvssMetricV2': [{'baseSeverity': 'HIGH'}]}
                    }
                }
            ]
        }

    @patch('requests.get')
    def test_search_by_software_cpe(self, mock_requests_get):
        mock_requests_get.return_value.json.return_value = self.mock_response
        cpe = CPENotation("cpe:2.3:o:linux:linux_kernel", "2.2", "2.6")
        cve_data = search_by_software_cpe(cpe)
        self.assertEqual(len(cve_data), 2)
        self.assertEqual(cve_data[0]['CVE'], 'CVE-2022-1234')
        self.assertEqual(cve_data[1]['CVE'], 'CVE-2022-5678')

    def test_get_base_severity(self):
        cve_data = self.mock_response['vulnerabilities'][0]['cve']
        base_severity = get_base_severity(cve_data)
        self.assertEqual(base_severity, 'LOW')

    def test_get_description(self):
        cve_data = self.mock_response['vulnerabilities'][0]
        description = get_description(cve_data)
        self.assertEqual(description, 'A sample CVE description')

    def test_count_cves_per_product(self):
        cves_data = {
            CPENotation("cpe:2.3:o:linux:linux_kernel"): [
                {'CVE': 'CVE-2022-1234'},
                {'CVE': 'CVE-2022-5678'}
            ],
            CPENotation("cpe:2.3:o:microsoft:windows_10:1511"): [
                {'CVE': 'CVE-2022-9012'}
            ]
        }
        cves_per_product_cnt = count_cves_per_product(cves_data)
        self.assertEqual(len(cves_per_product_cnt), 2)
        self.assertEqual(cves_per_product_cnt["cpe:2.3:o:linux:linux_kernel"], 2)
        self.assertEqual(cves_per_product_cnt["cpe:2.3:o:microsoft:windows_10:1511"], 1)

    def test_count_severities_distribution(self):
        cves_data = {
            CPENotation("cpe:2.3:o:linux:linux_kernel"): [
                {'cve': {'metrics': {'cvssMetricV2': [{'baseSeverity': 'LOW'}]}}},
                {'cve': {'metrics': {'cvssMetricV2': [{'baseSeverity': 'HIGH'}]}}}
            ]
        }
        severity_distribution = count_severities_distribution(cves_data)
        self.assertEqual(severity_distribution['LOW'], 1)
        self.assertEqual(severity_distribution['HIGH'], 1)


    def test_generate_report(self):
        cpe1 = CPENotation("cpe:2.3:o:linux:linux_kernel", "2.2", "2.6")
        cpe2 = CPENotation("cpe:2.3:o:microsoft:windows_10:1511")
        cpeArr = [cpe1, cpe2]
        report, visualizations = generate_report(cpeArr)
        self.assertNotEqual(report, '')
        clean_system(visualizations)


if __name__ == '__main__':
    unittest.main()
