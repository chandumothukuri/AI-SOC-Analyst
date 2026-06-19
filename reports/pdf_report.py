from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(
    report_text,
    filename
):

    pdf = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    content = []

    for line in report_text.split("\n"):

        content.append(
            Paragraph(
                line,
                styles["BodyText"]
            )
        )

        content.append(
            Spacer(1, 4)
        )

    pdf.build(content)