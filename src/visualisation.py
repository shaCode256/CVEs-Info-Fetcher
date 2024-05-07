# Visualization functions

import matplotlib.pyplot as plt
import numpy as np


def create_visualizations(cves_per_product_cnt,
                          high_severity_cves_per_product_cnt,
                          severity_distribution,
                          severity_distribution_per_product,
                          product_names):
    """

    :param cves_per_product_cnt:
    :param high_severity_cves_per_product_cnt:
    :param severity_distribution:
    :param severity_distribution_per_product:
    :param product_names:
    :return:
    """
    return {
        visualize_cves_per_product(cves_per_product_cnt),
        visualize_high_severity_cves_per_product(high_severity_cves_per_product_cnt),
        visualize_severity_distribution(severity_distribution),
        visualize_severity_distribution_per_product(severity_distribution_per_product, product_names),
        visualize_cves_heatmap(severity_distribution_per_product, product_names)}


def visualize_cves_per_product(cves_per_product_cnt):
    """

    :param cves_per_product_cnt:
    :return:
    """
    product_names = list(cves_per_product_cnt.keys())
    cve_counts = list(cves_per_product_cnt.values())

    plt.figure(figsize=(10, 6))
    bars = plt.bar(product_names, cve_counts, color='skyblue')
    plt.xlabel('Product')
    plt.ylabel('Number of CVEs')
    plt.title('Number of CVEs per Product')
    # Set text direction to right-to-left
    for bar in bars:
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05, bar.get_height(), ha='center', va='bottom',
                 rotation=90, fontname='Arial', fontsize=10, fontweight='bold')

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    # Save the plot to a file
    plt.savefig('cves_per_product.jpg')
    return 'cves_per_product.jpg'


def visualize_high_severity_cves_per_product(high_severity_cves_per_product_cnt):
    """

    :param high_severity_cves_per_product_cnt:
    :return:
    """
    product_names = list(high_severity_cves_per_product_cnt.keys())
    high_severity_cve_cnt = list(high_severity_cves_per_product_cnt.values())

    plt.figure(figsize=(10, 6))
    bars = plt.bar(product_names, high_severity_cve_cnt, color='salmon')
    plt.xlabel('Product')
    plt.ylabel('Number of High Severity CVEs')
    plt.title('Number of High Severity CVEs per Product')

    # Set text direction to right-to-left
    for bar in bars:
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05, bar.get_height(), ha='center', va='bottom',
                 rotation=90, fontname='Arial', fontsize=10, fontweight='bold')

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # Save the plot to a file
    plt.savefig('high_severity_cves_per_product.jpg')

    return 'high_severity_cves_per_product.jpg'


def visualize_severity_distribution(severity_distribution):
    """

    :param severity_distribution:
    :return:
    """
    severity_levels = list(severity_distribution.keys())
    severity_counts = list(severity_distribution.values())
    plt.figure(figsize=(8, 8))
    plt.pie(severity_counts, labels=severity_levels, autopct='%1.1f%%',
            colors=['lightgreen', 'skyblue', 'salmon', 'orange'])
    plt.title('Distribution of Severities Across All CVEs')
    # Save the plot to a file
    plt.savefig('severity_distribution.jpg')

    return 'severity_distribution.jpg'


def visualize_severity_distribution_per_product(severity_distribution_per_product, product_names):
    """

    :param severity_distribution_per_product:
    :param product_names:
    :return:
    """
    severity_levels = list(severity_distribution_per_product[product_names[0]].keys())

    plt.figure(figsize=(10, 6))
    bottom = None
    for severity in severity_levels:
        counts = [severity_distribution_per_product[product][severity] for product in product_names]
        plt.bar(product_names, counts, bottom=bottom, label=severity)
        if bottom is None:
            bottom = counts
        else:
            bottom = [bottom[i] + counts[i] for i in range(len(product_names))]

    plt.xlabel('Product')
    plt.ylabel('Number of CVEs')
    plt.title('Distribution of Severities per Product')
    plt.xticks(rotation=45, ha='right')
    plt.legend(title='Severity')
    plt.tight_layout()
    # Save the plot to a file
    plt.savefig('severity_distribution_per_product.jpg')

    return 'severity_distribution_per_product.jpg'


def visualize_cves_heatmap(severity_distribution_per_product, product_names):
    """

    :param severity_distribution_per_product:
    :param product_names:
    :return:
    """
    severity_levels = list(severity_distribution_per_product[product_names[0]].keys())
    severity_matrix = np.array(
        [[severity_distribution_per_product[product][severity] for severity in severity_levels] for product in
         product_names])

    plt.figure(figsize=(10, 8))
    plt.imshow(severity_matrix, cmap='viridis', interpolation='nearest')
    plt.colorbar(label='Number of CVEs')
    plt.xlabel('Severity')
    plt.ylabel('Product')
    plt.title('Matrix of Products vs. Severities')
    plt.xticks(ticks=np.arange(len(severity_levels)), labels=severity_levels)
    plt.yticks(ticks=np.arange(len(product_names)), labels=product_names)
    plt.tight_layout()
    # Save the plot to a file
    plt.savefig('cves_heatmap.jpg')

    return 'cves_heatmap.jpg'
