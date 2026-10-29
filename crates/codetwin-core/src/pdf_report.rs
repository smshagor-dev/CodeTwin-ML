//! Dependency-free PDF rendering of Markdown workflow reports.
//!
//! The output is a plain PDF 1.4 document using the standard Type 1 fonts
//! (Helvetica, Helvetica-Bold, Courier) with WinAnsi encoding, so it needs
//! no font files and renders identically everywhere. The renderer handles the
//! Markdown subset the report composer emits: headings, paragraphs, bullet
//! lists, tables and fenced code. Characters outside WinAnsi become `?`.
//! The document embeds the SHA-256 of the source Markdown, so a PDF can be
//! matched to the stored report it was produced from.

const PAGE_W: f64 = 595.0; // A4 in points
const PAGE_H: f64 = 842.0;
const MARGIN: f64 = 50.0;
const FOOTER: f64 = 30.0;

#[derive(Clone, Copy, PartialEq)]
enum Font {
    Regular,
    Bold,
    Mono,
}

impl Font {
    fn name(self) -> &'static str {
        match self {
            Font::Regular => "F1",
            Font::Bold => "F2",
            Font::Mono => "F3",
        }
    }
    /// Conservative average glyph width in em (Courier is exact).
    fn em(self) -> f64 {
        match self {
            Font::Regular => 0.52,
            Font::Bold => 0.56,
            Font::Mono => 0.6,
        }
    }
}

struct Line {
    font: Font,
    size: f64,
    indent: f64,
    text: String,
    gap_before: f64,
}

fn to_win_ansi(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\t' => ' ',
            '\u{2018}' | '\u{2019}' => '\'',
            '\u{201C}' | '\u{201D}' => '"',
            '\u{2013}' | '\u{2014}' => '-',
            '\u{2026}' => '.',
            '\u{2192}' => '>',
            c if (' '..='~').contains(&c) => c,
            c if ('\u{A0}'..='\u{FF}').contains(&c) => c,
            _ => '?',
        })
        .collect()
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

fn wrap(text: &str, font: Font, size: f64, width: f64) -> Vec<String> {
    let max = ((width / (font.em() * size)).floor() as usize).max(8);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split(' ') {
        let mut word = word.to_owned();
        while word.chars().count() > max {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let head: String = word.chars().take(max).collect();
            word = word.chars().skip(max).collect();
            lines.push(head);
        }
        let needed =
            current.chars().count() + usize::from(!current.is_empty()) + word.chars().count();
        if needed > max && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&word);
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

fn strip_inline(text: &str) -> String {
    let text = text.replace("**", "").replace('`', "");
    // Whole-span `_emphasis_`; underscores inside identifiers stay.
    let text = match text.strip_prefix('_').and_then(|t| t.strip_suffix('_')) {
        Some(inner) if !inner.is_empty() && !inner.ends_with('\\') => inner.to_owned(),
        _ => text,
    };
    // Drop Markdown backslash escapes (`\_`, `\|`, `\*`, ...).
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match chars.peek() {
            Some(&next) if c == '\\' && next.is_ascii_punctuation() => {
                out.push(next);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}

fn layout(markdown: &str) -> Vec<Line> {
    let width = PAGE_W - 2.0 * MARGIN;
    let mut out = Vec::new();
    let mut in_code = false;
    let push = |out: &mut Vec<Line>, text: &str, font, size, indent: f64, gap: f64| {
        for (i, l) in wrap(&to_win_ansi(text), font, size, width - indent)
            .into_iter()
            .enumerate()
        {
            out.push(Line {
                font,
                size,
                indent,
                text: l,
                gap_before: if i == 0 { gap } else { 0.0 },
            });
        }
    };
    for raw in markdown.lines() {
        let line = raw.trim_end();
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            push(&mut out, line, Font::Mono, 8.5, 10.0, 0.0);
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(h) = trimmed.strip_prefix("# ") {
            push(&mut out, &strip_inline(h), Font::Bold, 17.0, 0.0, 10.0);
        } else if let Some(h) = trimmed.strip_prefix("## ") {
            push(&mut out, &strip_inline(h), Font::Bold, 13.5, 0.0, 12.0);
        } else if let Some(h) = trimmed.strip_prefix("### ") {
            push(&mut out, &strip_inline(h), Font::Bold, 11.5, 0.0, 8.0);
        } else if trimmed.starts_with('|') {
            if trimmed.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')) {
                continue; // table separator row
            }
            let cells: Vec<String> = trimmed
                .trim_matches('|')
                .split(" | ")
                .map(|c| strip_inline(c.trim()))
                .collect();
            push(&mut out, &cells.join("  |  "), Font::Mono, 8.0, 0.0, 1.0);
        } else if let Some(item) = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
        {
            let depth = (line.len() - trimmed.len()) as f64 / 2.0;
            push(
                &mut out,
                &format!("- {}", strip_inline(item)),
                Font::Regular,
                10.0,
                12.0 + depth * 10.0,
                2.0,
            );
        } else {
            push(
                &mut out,
                &strip_inline(trimmed),
                Font::Regular,
                10.0,
                0.0,
                4.0,
            );
        }
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Render `markdown` to PDF bytes.
pub fn render_pdf(title: &str, markdown: &str) -> Vec<u8> {
    let lines = layout(markdown);
    let digest = sha256_hex(markdown.as_bytes());
    // Paginate.
    let mut pages: Vec<Vec<(f64, &Line)>> = vec![Vec::new()];
    let mut y = PAGE_H - MARGIN;
    for line in &lines {
        let step = line.gap_before + line.size * 1.3;
        if y - step < MARGIN + FOOTER {
            pages.push(Vec::new());
            y = PAGE_H - MARGIN;
        }
        y -= step;
        pages.last_mut().expect("page").push((y, line));
    }
    let total = pages.len();
    let footer_text = |n: usize| {
        escape(&to_win_ansi(&format!(
            "{} - page {n} of {total} - source sha256 {}",
            title.chars().take(60).collect::<String>(),
            &digest[..16]
        )))
    };

    // Objects: 1 catalog, 2 pages, 3-5 fonts, 6 info, then (page, content) pairs.
    let mut objects: Vec<Vec<u8>> = Vec::new();
    let first_page = 7;
    let kids: Vec<String> = (0..total)
        .map(|i| format!("{} 0 R", first_page + 2 * i))
        .collect();
    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    objects.push(
        format!(
            "<< /Type /Pages /Count {total} /Kids [{}] >>",
            kids.join(" ")
        )
        .into_bytes(),
    );
    for base in ["Helvetica", "Helvetica-Bold", "Courier"] {
        objects.push(
            format!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>"
            )
            .into_bytes(),
        );
    }
    objects.push(
        format!(
            "<< /Title ({}) /Producer (CodeTwin-ML) /Subject (source-sha256 {digest}) >>",
            escape(&to_win_ansi(title))
        )
        .into_bytes(),
    );
    for (i, page) in pages.iter().enumerate() {
        let mut content = String::from("BT\n");
        for (y, line) in page {
            content.push_str(&format!(
                "/{} {:.1} Tf 1 0 0 1 {:.1} {:.1} Tm ({}) Tj\n",
                line.font.name(),
                line.size,
                MARGIN + line.indent,
                y,
                escape(&line.text)
            ));
        }
        content.push_str(&format!(
            "/F1 7.5 Tf 1 0 0 1 {MARGIN:.1} {:.1} Tm ({}) Tj\nET\n",
            MARGIN - 8.0,
            footer_text(i + 1)
        ));
        let content_id = first_page + 2 * i + 1;
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] \
                 /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {content_id} 0 R >>"
            )
            .into_bytes(),
        );
        let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
        stream.extend_from_slice(content.as_bytes());
        stream.extend_from_slice(b"endstream");
        objects.push(stream);
    }

    let mut pdf: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        pdf.extend_from_slice(body);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for off in offsets {
        pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xref_offsets(pdf: &[u8]) -> Vec<usize> {
        let text = String::from_utf8_lossy(pdf);
        let start: usize = text
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        text[start..]
            .lines()
            .skip(3)
            .take_while(|l| l.ends_with(" n "))
            .map(|l| l[..10].parse().unwrap())
            .collect()
    }

    #[test]
    fn produces_a_structurally_valid_multipage_pdf() {
        let mut md = String::from("# Run report (verified)\n\n## Findings\n\n| a | b |\n|---|---|\n| x | y |\n\n```\nfn main() {}\n```\n");
        for i in 0..200 {
            md.push_str(&format!(
                "- item {i} with (parens) and \\ backslash → arrow and 日本\n"
            ));
        }
        let pdf = render_pdf("Report", &md);
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        let offsets = xref_offsets(&pdf);
        for (i, off) in offsets.iter().enumerate() {
            let expect = format!("{} 0 obj", i + 1);
            assert_eq!(
                &pdf[*off..*off + expect.len()],
                expect.as_bytes(),
                "object {}",
                i + 1
            );
        }
        let text = String::from_utf8_lossy(&pdf);
        let pages: usize = text
            .split("/Type /Pages /Count ")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(pages >= 3, "{pages}");
        assert!(text.contains("\\(parens\\)"));
        assert!(text.contains("??"), "non-WinAnsi characters are replaced");
        assert!(text.contains(&sha256_hex(md.as_bytes())));
    }

    #[test]
    fn markdown_escapes_and_emphasis_are_not_printed() {
        assert_eq!(
            strip_inline("evidence qa\\_artifact a\\|b"),
            "evidence qa_artifact a|b"
        );
        assert_eq!(strip_inline("_None._"), "None.");
        assert_eq!(strip_inline("qa_planner ran"), "qa_planner ran");
        assert_eq!(strip_inline("**bold** `code`"), "bold code");
    }

    #[test]
    fn long_words_wrap() {
        let lines = wrap(&"x".repeat(500), Font::Regular, 10.0, 200.0);
        assert!(lines.len() > 5);
        assert!(lines.iter().all(|l| l.len() <= 38));
    }
}
