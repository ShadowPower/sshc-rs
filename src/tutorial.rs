use crate::Asset;
use anstyle::{AnsiColor, Color, Style};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    style::Print,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::{stdout, Stdout, Write};

type StyledLine = Vec<(String, Style)>;

pub fn show() -> Result<()> {
    let content = Asset::get("TUTORIAL.md").expect("教程文件未嵌入");
    let tutorial_text = std::str::from_utf8(&content.data)?;
    let styled_lines = parse_and_style_tutorial(tutorial_text);

    let mut stdout = stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;

    let result = run_viewer_loop(&mut stdout, &styled_lines);

    execute!(stdout, LeaveAlternateScreen)?;
    disable_raw_mode()?;

    result
}

fn run_viewer_loop(stdout: &mut Stdout, lines: &[StyledLine]) -> Result<()> {
    let mut top_line = 0;

    loop {
        let (width, height) = crossterm::terminal::size()?;
        let height = height as usize;
        let visible_height = height.saturating_sub(1);
        let total_lines = lines.len();

        render_screen(stdout, lines, top_line, height, width as usize)?;

        if let Event::Key(key_event) = event::read()? {
            match key_event.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Up | KeyCode::Char('k') => {
                    top_line = top_line.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if total_lines > visible_height
                        && top_line < total_lines.saturating_sub(visible_height)
                    {
                        top_line += 1;
                    }
                }
                KeyCode::PageUp => {
                    top_line = top_line.saturating_sub(visible_height);
                }
                KeyCode::PageDown => {
                    if total_lines > visible_height {
                        top_line = (top_line + visible_height)
                            .min(total_lines.saturating_sub(visible_height));
                    }
                }
                KeyCode::Home => top_line = 0,
                KeyCode::End => {
                    if total_lines > visible_height {
                        top_line = total_lines.saturating_sub(visible_height);
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn render_screen(
    stdout: &mut Stdout,
    lines: &[StyledLine],
    top_line: usize,
    height: usize,
    width: usize,
) -> Result<()> {
    crossterm::queue!(
        stdout,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::cursor::MoveTo(0, 0)
    )?;

    let visible_height = height.saturating_sub(1);
    for i in 0..visible_height {
        if let Some(line_content) = lines.get(top_line + i) {
            for (text, style) in line_content {
                crossterm::queue!(
                    stdout,
                    Print(format_args!(
                        "{}{}{}",
                        style.render(),
                        text,
                        style.render_reset()
                    ))
                )?;
            }
        }
        if i < visible_height - 1 {
            writeln!(stdout, "\r")?;
        }
    }

    let status = format!(
        "↑↓/jk:滚动 PgUp/PgDn:翻页 Home/End:首尾 q/ESC:退出 (行 {}/{})",
        top_line + 1,
        lines.len()
    );
    let padding = " ".repeat(width.saturating_sub(status.len()));
    let status_style = Style::new().invert();
    crossterm::queue!(
        stdout,
        crossterm::cursor::MoveTo(0, height.saturating_sub(1) as u16),
        Print(format_args!(
            "{}{}{}",
            status_style.render(),
            status,
            status_style.render_reset()
        )),
        Print(format_args!(
            "{}{}{}",
            status_style.render(),
            padding,
            status_style.render_reset()
        ))
    )?;

    stdout.flush()?;
    Ok(())
}

fn parse_and_style_tutorial(text: &str) -> Vec<StyledLine> {
    let h2_style = Style::new()
        .bold()
        .fg_color(Some(Color::Ansi(AnsiColor::Cyan)));
    let h3_style = Style::new()
        .bold()
        .fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
    let h4_style = Style::new()
        .bold()
        .underline()
        .fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
    let code_style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));
    let placeholder_style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Magenta)));
    let default_style = Style::new();

    text.lines()
        .map(|line| {
            let (line_text, base_style) = if line.starts_with("#### ") {
                (&line[5..], h4_style)
            } else if line.starts_with("### ") {
                (&line[4..], h3_style)
            } else if line.starts_with("## ") {
                (&line[3..], h2_style)
            } else {
                (line, default_style)
            };
            parse_inline_styles(line_text, base_style, code_style, placeholder_style)
        })
        .collect()
}

fn parse_inline_styles(
    line: &str,
    base_style: Style,
    code_style: Style,
    placeholder_style: Style,
) -> StyledLine {
    let mut segments = Vec::new();
    let mut current_pos = 0;

    while let Some(start) = line[current_pos..].find('`') {
        let pre_text = &line[current_pos..current_pos + start];
        if !pre_text.is_empty() {
            segments.push((pre_text.to_string(), base_style));
        }

        let code_start = current_pos + start + 1;
        if let Some(end) = line[code_start..].find('`') {
            let code_end = code_start + end;
            let code_part = &line[code_start..code_end];

            let mut inner_pos = 0;
            while let Some(ph_start) = code_part[inner_pos..].find('<') {
                let pre_code = &code_part[inner_pos..inner_pos + ph_start];
                if !pre_code.is_empty() {
                    segments.push((pre_code.to_string(), code_style));
                }

                let ph_full_start = inner_pos + ph_start;
                if let Some(ph_end) = code_part[ph_full_start..].find('>') {
                    let ph_full_end = ph_full_start + ph_end + 1;
                    segments.push((
                        code_part[ph_full_start..ph_full_end].to_string(),
                        placeholder_style,
                    ));
                    inner_pos = ph_full_end;
                } else {
                    inner_pos = ph_full_start + 1;
                    break;
                }
            }
            if inner_pos < code_part.len() {
                segments.push((code_part[inner_pos..].to_string(), code_style));
            }

            current_pos = code_end + 1;
        } else {
            segments.push(("`".to_string(), base_style));
            current_pos = code_start;
            break;
        }
    }

    if current_pos < line.len() {
        segments.push((line[current_pos..].to_string(), base_style));
    }

    if segments.is_empty() && !line.is_empty() {
        vec![(line.to_string(), base_style)]
    } else {
        segments
    }
}
