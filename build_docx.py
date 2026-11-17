"""Build Medium-Article.docx from MEDIUM-ARTICLE.md.

Handles the subset of markdown used in that file: h1/h2, paragraphs, fenced
code, images with a following italic caption, horizontal rules, inline bold and
backticks. Images are embedded at 6 inches wide.
"""
import os
import re

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "MEDIUM-ARTICLE.md")
OUT = os.path.join(HERE, "Medium-Article.docx")
META = {
    "Subtitle": "A fake update screen, three keystrokes, and a Base64 string that "
                "downloads whatever the attacker feels like running.",
    "Tags": "Cybersecurity, Malware Analysis, PowerShell, Phishing, Threat Intelligence",
}


def shade(paragraph, hex_fill="F2F2F2"):
    pPr = paragraph._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    pPr.append(shd)


def add_inline(paragraph, text):
    """Split on **bold** and `code` and add runs accordingly."""
    for part in re.split(r"(\*\*.+?\*\*|`[^`]+`)", text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            run = paragraph.add_run(part[2:-2])
            run.bold = True
        elif part.startswith("`") and part.endswith("`"):
            run = paragraph.add_run(part[1:-1])
            run.font.name = "Consolas"
            run.font.size = Pt(10)
        else:
            paragraph.add_run(part)


def main():
    with open(SRC, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Georgia"
    style.font.size = Pt(11.5)
    style.paragraph_format.space_after = Pt(9)
    style.paragraph_format.line_spacing = 1.35

    i = 0
    pending_caption = False

    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()

        # fenced code block
        if line.startswith("```"):
            i += 1
            block = []
            while i < len(lines) and not lines[i].startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            for code_line in block or [""]:
                p = doc.add_paragraph()
                p.paragraph_format.space_after = Pt(0)
                p.paragraph_format.line_spacing = 1.15
                shade(p)
                run = p.add_run(code_line)
                run.font.name = "Consolas"
                run.font.size = Pt(9.5)
            doc.add_paragraph().paragraph_format.space_after = Pt(6)
            continue

        if line.startswith("# "):
            h = doc.add_heading(line[2:].strip(), level=0)
            h.alignment = WD_ALIGN_PARAGRAPH.LEFT
            i += 1
            continue

        if line.startswith("## "):
            doc.add_heading(line[3:].strip(), level=1)
            i += 1
            continue

        if line.strip() == "---":
            i += 1
            continue

        m = re.match(r"!\[(.*?)\]\((.*?)\)", line.strip())
        if m:
            alt, rel = m.group(1), m.group(2)
            path = os.path.join(HERE, rel.replace("/", os.sep))
            if os.path.exists(path):
                pic = doc.add_paragraph()
                pic.alignment = WD_ALIGN_PARAGRAPH.CENTER
                pic.paragraph_format.space_before = Pt(8)
                pic.paragraph_format.space_after = Pt(2)
                pic.add_run().add_picture(path, width=Inches(6))
            else:
                doc.add_paragraph(f"[missing image: {rel}]")
            pending_caption = True
            i += 1
            continue

        if pending_caption and line.strip().startswith("*") and line.strip().endswith("*"):
            cap = doc.add_paragraph()
            cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = cap.add_run(line.strip().strip("*"))
            run.italic = True
            run.font.size = Pt(9)
            run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)
            pending_caption = False
            i += 1
            continue

        if not line.strip():
            i += 1
            continue

        if line.startswith("**Tags:**") or line.startswith("**Subtitle:**"):
            key, _, val = line.partition(":**")
            p = doc.add_paragraph()
            run = p.add_run(key.replace("**", "") + ": ")
            run.bold = True
            add_inline(p, val.lstrip(":").strip())
            i += 1
            continue

        p = doc.add_paragraph()
        add_inline(p, line.strip())
        i += 1

    # metadata block on a final page
    doc.add_page_break()
    doc.add_heading("Publication details", level=1)
    for key, value in META.items():
        p = doc.add_paragraph()
        run = p.add_run(f"{key}: ")
        run.bold = True
        add_inline(p, value)

    doc.save(OUT)
    print(f"wrote {OUT}")
    print(f"paragraphs: {len(doc.paragraphs)}")
    print(f"images: {len(doc.inline_shapes)}")


if __name__ == "__main__":
    main()
