import logging
import re
from typing import List, Dict

import requests

CVE_API_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CPENotation:
    """

    """
    def __init__(self, name, version_start=None, version_end=None):
        self.name = name
        self.version_start = version_start
        self.version_end = version_end
        self.validate_version()
        self.validate_cpe_name()

    def _valid_cpe(self, cpe):
        # Use regular expression matching to validate the format
        pattern = r'^cpe:2\.3:[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+(?::[a-zA-Z0-9._-]+){0,9}$'
        return re.match(pattern, cpe) is not None

    def validate_version(self):
        """

        """
        if self.version_start is not None and self.version_end is not None:
            if not self._is_numeric(self.version_start) or not self._is_numeric(self.version_end):
                raise ValueError("Version numbers must be numeric.")
            elif float(self.version_start) >= float(self.version_end):
                raise ValueError("Version start must be less than version end.")

    def validate_cpe_name(self):
        """

        """
        if not self._valid_cpe(self.name):
            raise ValueError("CPE value is not valid.")

    def _is_numeric(self, value):
        try:
            float(value)
            return True
        except ValueError:
            return False

    def __str__(self):
        """
        Return a string representation of the CPENotation object.
        """
        if self.version_start is not None and self.version_end is not None:
            return f"CPENotation(name={self.name}, version_start={self.version_start}, version_end={self.version_end})"
        elif self.version_start is not None:
            return f"CPENotation(name={self.name}, version_start={self.version_start})"
        elif self.version_end is not None:
            return f"CPENotation(name={self.name}, version_end={self.version_end})"
        else:
            return f"CPENotation(name={self.name})"


def search_by_software_cpe(cpe: CPENotation) -> List[Dict]:
    """

    :param cpe:
    :return:
    """
    try:
        print(f"Fetching the CVE database API for {cpe.name} ...")
        api_endpoint = f"{CVE_API_ENDPOINT}&virtualMatchString={cpe.name}"
        if cpe.version_start:
            api_endpoint += f"&versionStart={cpe.version_start}&versionStartType=including"
        if cpe.version_end:
            api_endpoint += f"&versionEnd={cpe.version_end}&versionEndType=including"

        response = requests.get(api_endpoint)
        response.raise_for_status()  # Raise exception for non-200 response
        return response.json()['vulnerabilities']
    except Exception as e:
        logger.error(f"Error searching for CVEs by software cpe: {e}")
        return []


def get_base_severity(cve_data: str) -> str:
    """

    :param cve_data:
    :return:
    """
    base_severity = cve_data['metrics']['cvssMetricV2'][0]['baseSeverity']
    return base_severity


###
def get_description(cve_data: str) -> str:
    """

    :param cve_data:
    :return:
    """
    descs = cve_data['cve']['descriptions']
    en_description = "No English description"
    for desc in descs:
        if desc['lang'] == 'en':
            en_description = desc['value']
    return en_description


def extract_cve_info(data):
    """

    :param data:
    :return:
    """
    try:
        # Extract desired information
        cve_id = data['cve']['id']
        base_severity = data['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
        last_modified = data['cve']['lastModified']
        description = data['cve']['descriptions'][0]['value']
        base_score = data['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']

        # Create dictionary with extracted information
        extracted_info = {
            "CVE ID": cve_id,
            "Base Severity": base_severity,
            "Last Modified": last_modified,
            "Description": description,
            "Base Score": base_score
        }

        return extracted_info

    except Exception as e:
        return f"Error generating weakness report: {e}"
