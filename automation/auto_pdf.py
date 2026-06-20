from reports.pdf_report import generate_pdf_report


def create_pdf(report, alert_name):

    filename = (
        "output/"
        + alert_name.replace(" ", "_").lower()
        + "_auto_report.pdf"
    )

    generate_pdf_report(
        report,
        filename
    )

    return filename