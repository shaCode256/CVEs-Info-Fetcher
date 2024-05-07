# Main file
from cryptography.fernet import Fernet
from src.data_fetch import CPENotation
from report import generate_report, encrypt_report, decrypt_report, save_to_pdf
from utils import clean_system, save_bytes_to_file


# Example usage
def main():
    """

    """
    key = Fernet.generate_key()
    # Create a new CPENotation instance with validation
    cpe1 = CPENotation("cpe:2.3:o:linux:linux_kernel", version_start="2.0", version_end="2.6")
    # Create a new CPENotation instance with validation
    cpe2 = CPENotation("cpe:2.3:o:microsoft:windows_10:1511")

    cpeArr = [cpe1, cpe2]
    print("Start ... ")
    print("Please wait... ")
    detailed_report, visualization_figures = generate_report(cpeArr)
    print("Done processing info ... ")
    save_to_pdf(detailed_report, '../report_with_visualizations.pdf', visualization_figures)
    print("Saved Report to PDF named 'report_with_visualizations.pdf'")
    clean_system(visualization_figures)
    # print(detailed_report)
    print("Start Encrypting Report")
    # encrypt the report
    encrypted_report = encrypt_report(detailed_report, key)
    # print("Encrypted Report:", encrypted_report)
    save_bytes_to_file(encrypted_report, "../encrypted_report.txt")
    print("Done Encrypting Report, saved to 'encrypted_report.txt")
    # print("key: ", key)
    print("TIP: you can get the key uncommenting above next run")

    # Decrypt the encrypted report
    decrypted_report = decrypt_report(encrypted_report, key)
    # print("Decrypted Report:", decrypted_report)


if __name__ == "__main__":
    main()
