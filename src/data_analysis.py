from typing import List, Dict

# Data analysis functions
from src.data_fetch import get_base_severity


def count_cves_per_product(cves_data):
    """

    :param cves_data:
    :return:
    """
    cves_per_product_cnt = {}
    for cpe, cves in cves_data.items():
        cves_per_product_cnt[cpe.name] = len(cves)
    return cves_per_product_cnt


def count_high_severity_cves_per_product(cves_data):
    """

    :param cves_data:
    :return:
    """
    high_severity_cves_per_product_cnt = {}
    for cpe, cves in cves_data.items():
        high_severity_cves = [cve for cve in cves if cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'] == 'HIGH']
        high_severity_cves_per_product_cnt[cpe.name] = len(high_severity_cves)
    return high_severity_cves_per_product_cnt


def count_severities_distribution(cves_data):
    """

    :param cves_data:
    :return:
    """
    print("In data analysis...")
    severity_distribution = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
    for cpe, cves in cves_data.items():
        for cve in cves:
            base_severity = cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
           # print(base_severity)
            if base_severity in severity_distribution:
                severity_distribution[base_severity] += 1
    return severity_distribution


def count_severities_distribution_per_product(cves_data):
    """

    :param cves_data:
    :return:
    """
    severity_distribution_per_product = {}
    for cpe, cves in cves_data.items():
        low_severity_cves = [cve for cve in cves if cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'] == 'LOW']
        medium_severity_cves = [cve for cve in cves if
                                cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'] == 'MEDIUM']
        high_severity_cves = [cve for cve in cves if cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'] == 'HIGH']
        severity_distribution_per_product[cpe.name] = {
            'low': len(low_severity_cves),
            'medium': len(medium_severity_cves),
            'high': len(high_severity_cves)
        }
    return severity_distribution_per_product


def get_product_names(cves_data):
    """

    :param cves_data:
    :return:
    """
    product_names = []
    for cpe in cves_data.keys():
        product_names.append(cpe.name)
    return product_names


# Function to sort CVEs by vulnerability score
def sort_by_vulnerability_score(cves_data: List[Dict]) -> List[Dict]:
    """

    :param cves_data:
    :return:
    """
    return sorted(cves_data, key=lambda x: get_base_severity(x), reverse=True)
