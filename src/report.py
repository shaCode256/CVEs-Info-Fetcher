from PIL import Image as PILImage
from cryptography.fernet import Fernet
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Image as RLImage
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.platypus.para import Paragraph
from src.data_analysis import count_cves_per_product, count_high_severity_cves_per_product, count_severities_distribution, \
    count_severities_distribution_per_product, get_product_names
from src.data_fetch import search_by_software_cpe, extract_cve_info
from src.visualisation import create_visualizations


# Report Function

def generate_detailed_report(total_cves, cves_per_product_cnt, most_cves_product, severity_distribution,
                             severity_distribution_per_product, cpes_cves_data):
    """

    :param total_cves:
    :param cves_per_product_cnt:
    :param most_cves_product:
    :param severity_distribution:
    :param severity_distribution_per_product:
    :param cpes_cves_data:
    :return:
    """

    # Total CVEs analyzed
    detailed_report = f"*Total CVEs Analyzed: {total_cves}\n\n"
    detailed_report += " \n"

    # Total affected products
    detailed_report += f"*Total Affected Products: {len(cves_per_product_cnt)}\n\n"
    detailed_report += " \n"

    # Product with most CVEs
    detailed_report += f"*Product with Most CVEs: \n {most_cves_product}\n\n\n"
    detailed_report += " \n"

    # CVEs per product count
    detailed_report += "*CVEs per Product Count:\n\n"
    for product, cve_count in cves_per_product_cnt.items():
        detailed_report += f"- {product}: {cve_count}\n\n"
    detailed_report += "\n"
    detailed_report += " \n"

    # Severity distribution across all CVEs
    detailed_report += "*Severity Distribution Across All CVEs:\n\n"
    for severity, count in severity_distribution.items():
        detailed_report += f"- {severity}: {count}\n"
    detailed_report += "\n"
    detailed_report += " \n"

    # Severity distribution per product
    detailed_report += "*Severity Distribution Per Product:\n\n"
    for product, distribution in severity_distribution_per_product.items():
        detailed_report += f"{product}:\n"
        for severity, count in distribution.items():
            detailed_report += f"  - {severity}: {count}\n"
    detailed_report += "\n"
    detailed_report += " \n"

    # Severity distribution per product
    detailed_report += "*Detailed CVES data per product:\n"
    detailed_report += cpes_cves_data
    detailed_report += "\n"
    detailed_report += " \n"

    return detailed_report


def generate_weakness_report(cves_data):
    """

    :param cves_data:
    :return:
    """
    if not cves_data:
        print("No CVE data available.")
        return

    try:
        total_cves = sum(len(cves) for cves in cves_data.values())
        cves_per_product_cnt = count_cves_per_product(cves_data)
        high_severity_cves_per_product_cnt = count_high_severity_cves_per_product(cves_data)
        severity_distribution = count_severities_distribution(cves_data)

        severity_distribution_per_product = count_severities_distribution_per_product(cves_data)
        product_names = get_product_names(cves_data)
        most_cves_product = max(cves_per_product_cnt, key=cves_per_product_cnt.get)
        cpes_cves_info = {}
        for cpe in cves_data:
            cpes_cves_info[cpe.name] = []
            for cve in cves_data[cpe]:
                cpes_cves_info[cpe.name].append(extract_cve_info(cve))

        # Assuming cpes_cves_info is a dictionary
        cpes_cves_info_str = ""
        for cpe_name, cve_info_list in cpes_cves_info.items():
            cpes_cves_info_str += "\n" + str(cpe_name)
            for cve_info in cve_info_list:
                cpes_cves_info_str += "\n" + str(cve_info)

        # Call the function to generate detailed report
        detailed_report = generate_detailed_report(total_cves, cves_per_product_cnt, most_cves_product,
                                                   severity_distribution, severity_distribution_per_product,
                                                   cpes_cves_info_str)

        # Visualization functions
        visualization_figures = create_visualizations(cves_per_product_cnt, high_severity_cves_per_product_cnt,
                                                      severity_distribution, severity_distribution_per_product,
                                                      product_names)

        return detailed_report, visualization_figures

    except Exception as e:
        return f"Error generating weakness report: {e}"


def save_to_pdf(detailed_report, filename, visualization_figures=None):
    """

    :param detailed_report:
    :param filename:
    :param visualization_figures:
    """
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()

    # Define custom styles for CPE identifier and CVE information
    cpe_style = ParagraphStyle(name='CPE', fontName='Helvetica-Bold', fontSize=13)
    cve_style = ParagraphStyle(name='CVE', fontName='Helvetica', fontSize=10)
    title_style = ParagraphStyle(name='TITLE', fontName='Helvetica-Bold', fontSize=16)

    content = [Paragraph("Vulnerabilities Report", styles['Title']), Paragraph("", styles['Normal'])]

    # Add title

    # Split report into sections
    lines = detailed_report.split("\n")
    # Add report content
    for line in lines:
        # Add visualizations condition
        content.append(Paragraph("", styles['Normal']))
        if line.startswith("*Detailed CVES data per product"):
            # Add visualization figures if provided
            if visualization_figures:
                for plot_path in visualization_figures:
                    # Open the image using PIL
                    pil_image = PILImage.open(plot_path)
                    plot_name = plot_path
                    # Remove the ".jpg" extension
                    if plot_path.endswith(".jpg"):
                        plot_name = plot_path[:-4]
                    # Convert PIL image to ReportLab Image object
                    img = RLImage(plot_path, width=400, height=200)  # Adjust width and height as needed
                    content.append(img)
                    # Add empty line between figures
                    content.append(Paragraph("", styles['Normal']))
        if line.startswith('*'):
            content.append(Paragraph(line, title_style))
            content.append(Paragraph("", styles['Normal']))  # Add empty line between sections
        elif line.startswith('cpe'):
             content.append(Paragraph(line, cpe_style))
             content.append(Paragraph("", styles['Normal']))  # Add empty line between sections
        elif line.startswith('{'):
            content.append(Paragraph(line, cve_style))
        else:
            content.append(Paragraph(line, styles['Normal']))
        content.append(Paragraph("", styles['Normal']))  # Add empty line between sections


    doc.build(content)


def encrypt_report(report: str, key: bytes) -> bytes:
    """
    Encrypt the report using AES encryption with the provided key.
    """
    cipher = Fernet(key)
    encrypted_report = cipher.encrypt(report.encode())
    return encrypted_report


def decrypt_report(encrypted_report: bytes, key: bytes) -> str:
    """
    Decrypt the encrypted report using AES decryption with the provided key.
    """
    cipher = Fernet(key)
    decrypted_report = cipher.decrypt(encrypted_report).decode()
    return decrypted_report


def generate_report(cpe_arr):
    """

    :param cpe_arr:
    :return:
    """
    cves_data = {}
    for cpe in cpe_arr:
        cpe_data = search_by_software_cpe(cpe)
        cves_data[cpe] = cpe_data
    # print(cves_data)
    detailed_report, visualization_figures = generate_weakness_report(cves_data)
    return detailed_report, visualization_figures
