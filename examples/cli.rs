use file_info::Result;
use prettytable::{color, format::Alignment, Attr, Cell, Row, Table};

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        eprintln!("Usage:\n\t{} <file>", argv[0]);
        return Ok(());
    }
    let res = file_info::get_file_extended_information(&argv[1])?;

    // ================= Entry point table =================
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "Entry point",
        Alignment::CENTER,
    )
    .with_hspan(2)
    .with_style(Attr::Bold)
    .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))]));
    // Entry point
    if let Some(entry_point) = res.entry_point {
        tbl.add_row(Row::new(vec![
            Cell::new("Address"),
            Cell::new(&format!("{:#01x}", entry_point.address)),
        ]));
        if let Some(section) = entry_point.section {
            tbl.add_row(Row::new(vec![
                Cell::new("Section Name"),
                Cell::new(&section.name),
            ]));
            tbl.add_row(Row::new(vec![
                Cell::new("Virtual Address"),
                Cell::new(&format!("{:#01x}", section.virt_addr)),
            ]));
            tbl.add_row(Row::new(vec![
                Cell::new("Virtual Size"),
                Cell::new(&format!("{:#01x}", section.virt_size)),
            ]));
            tbl.add_row(Row::new(vec![
                Cell::new("Raw Address"),
                Cell::new(&format!("{:#01x}", section.raw_addr)),
            ]));
            tbl.add_row(Row::new(vec![
                Cell::new("Raw Size"),
                Cell::new(&format!("{:#01x}", section.raw_size)),
            ]));
            if let Some(entropy) = section.entropy {
                if entropy < 7_f32 {
                    tbl.add_row(Row::new(vec![
                        Cell::new("Entropy"),
                        Cell::new(&section.entropy.unwrap_or(0.0).to_string()),
                    ]));
                } else {
                    tbl.add_row(Row::new(vec![
                        Cell::new("Entropy"),
                        Cell::new(&section.entropy.unwrap_or(0.0).to_string())
                            .with_style(Attr::ForegroundColor(color::RED))
                            .with_style(Attr::Bold),
                    ]));
                }
            } else {
                tbl.add_row(Row::new(vec![Cell::new("Entropy"), Cell::new("0.0")]));
            }

            tbl.add_row(Row::new(vec![
                Cell::new("Characteristics"),
                Cell::new(
                    &section
                        .characteristics
                        .as_ref()
                        .unwrap_or(&String::from(""))
                        .to_string(),
                ),
            ]));
        }
    } else {
        tbl.add_row(Row::new(vec![Cell::new_align(
            "NO DATA",
            Alignment::CENTER,
        )
        .with_hspan(2)
        .with_style(Attr::Bold)
        .with_style(Attr::ForegroundColor(color::BLUE))]));
    }
    // Print the Entrypoint table
    tbl.printstd();

    // ================= Sections table =================
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "Sections",
        Alignment::CENTER,
    )
    .with_hspan(7)
    .with_style(Attr::Bold)
    .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))]));
    tbl.add_row(Row::new(vec![
        Cell::new("Name").with_style(Attr::Bold),
        Cell::new("Virtual Address").with_style(Attr::Bold),
        Cell::new("Virtual Address Size").with_style(Attr::Bold),
        Cell::new("Raw Address").with_style(Attr::Bold),
        Cell::new("Raw Address Size").with_style(Attr::Bold),
        Cell::new("Entropy").with_style(Attr::Bold),
        Cell::new("Characteristics").with_style(Attr::Bold),
    ]));
    if let Some(sections) = res.section_table {
        if !sections.sections.is_empty() {
            for v in sections.sections.iter() {
                tbl.add_row(Row::new(vec![
                    Cell::new(&v.name),
                    Cell::new(&format!("{:#01x}", v.virt_addr)),
                    Cell::new(&format!("{:#01x}", v.virt_size)),
                    Cell::new(&format!("{:#01x}", v.raw_addr)),
                    Cell::new(&format!("{:#01x}", v.raw_size)),
                    Cell::new(&v.entropy.unwrap_or(0.0).to_string()),
                    Cell::new(&v.clone().characteristics.unwrap_or_default().to_string()),
                ]));
            }
        } else {
            tbl.add_row(Row::new(vec![Cell::new_align(
                "NO DATA",
                Alignment::CENTER,
            )
            .with_hspan(7)
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::BLUE))]));
        }
    } else {
        tbl.add_row(Row::new(vec![Cell::new_align(
            "NO DATA",
            Alignment::CENTER,
        )
        .with_hspan(7)
        .with_style(Attr::Bold)
        .with_style(Attr::ForegroundColor(color::BLUE))]));
    }
    // Print the Sections table
    tbl.printstd();

    // ================= Rich Headers =================
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "Rich Headers",
        Alignment::CENTER,
    )
    .with_hspan(5)
    .with_style(Attr::Bold)
    .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))]));
    tbl.add_row(Row::new(vec![
        Cell::new("Product Name").with_style(Attr::Bold),
        Cell::new("Build").with_style(Attr::Bold),
        Cell::new("Product ID").with_style(Attr::Bold),
        Cell::new("Count").with_style(Attr::Bold),
        Cell::new("Guessed Visual Studio Version").with_style(Attr::Bold),
    ]));
    if let Some(rich_table) = res.rich_headers {
        if !rich_table.rich_entries.is_empty() {
            for v in rich_table.rich_entries.iter() {
                tbl.add_row(Row::new(vec![
                    Cell::new(&v.product_name),
                    Cell::new(&v.build.to_string()),
                    Cell::new(&v.product_id.to_string()),
                    Cell::new(&v.count.to_string()),
                    Cell::new(&v.guessed_visual_studio_version),
                ]));
            }
        } else {
            tbl.add_row(Row::new(vec![Cell::new_align(
                "NO DATA",
                Alignment::CENTER,
            )
            .with_hspan(5)
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::BLUE))]));
        }
    } else {
        tbl.add_row(Row::new(vec![Cell::new_align(
            "NO DATA",
            Alignment::CENTER,
        )
        .with_hspan(5)
        .with_style(Attr::Bold)
        .with_style(Attr::ForegroundColor(color::BLUE))]));
    }
    // Print the Rich Headers table
    tbl.printstd();

    // ================= Signatures =================
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "Signatures",
        Alignment::CENTER,
    )
    .with_hspan(2)
    .with_style(Attr::Bold)
    .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))]));
    if let Some(signatures) = res.signature {
        if !signatures.signatures.is_empty() {
            for (index, signature) in signatures.signatures.iter().enumerate() {
                tbl.add_row(Row::new(vec![Cell::new(&format!(
                    "Signature #{}",
                    index + 1
                ))
                .with_hspan(2)
                .with_style(Attr::ForegroundColor(color::MAGENTA))
                .with_style(Attr::Bold)]));

                tbl.add_row(Row::new(vec![Cell::new(&format!(
                    "Signature Digest: {}",
                    signature.digest
                ))
                .with_hspan(2)]));
                tbl.add_row(Row::new(vec![Cell::new("Signer")
                    .with_hspan(2)
                    .with_style(Attr::Bold)]));
                if let Some(issuer) = &signature.issuer {
                    tbl.add_row(Row::new(vec![
                        Cell::new("Issuer"),
                        Cell::new(&issuer.issuer),
                    ]));
                    tbl.add_row(Row::new(vec![
                        Cell::new("Serial Number"),
                        Cell::new(&issuer.serial_number),
                    ]));
                }

                for (idx, cert) in signature.certificates.iter().enumerate() {
                    tbl.add_row(Row::new(vec![Cell::new(&format!("Certificate #{}", idx))
                        .with_hspan(2)
                        .with_style(Attr::Bold)]));
                    tbl.add_row(Row::new(vec![
                        Cell::new("Certificate Issuer"),
                        Cell::new(&cert.issuer),
                    ]));
                    tbl.add_row(Row::new(vec![
                        Cell::new("Certificate Subject"),
                        Cell::new(&cert.subject),
                    ]));
                    tbl.add_row(Row::new(vec![
                        Cell::new("Certificate Serial Number"),
                        Cell::new(&cert.serial_number),
                    ]));
                }
            }
        } else {
            tbl.add_row(Row::new(vec![Cell::new_align(
                "NO DATA",
                Alignment::CENTER,
            )
            .with_hspan(2)
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::BLUE))]));
        }
    } else {
        tbl.add_row(Row::new(vec![Cell::new_align(
            "NO DATA",
            Alignment::CENTER,
        )
        .with_hspan(2)
        .with_style(Attr::Bold)
        .with_style(Attr::ForegroundColor(color::BLUE))]));
    }
    // Print the Signatures table
    tbl.printstd();

    // ================= Imports table =================
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "Imports",
        Alignment::CENTER,
    )
    .with_hspan(2)
    .with_style(Attr::Bold)
    .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))]));
    tbl.add_row(Row::new(vec![
        Cell::new("Module Name").with_style(Attr::Bold),
        Cell::new("Imports").with_style(Attr::Bold),
    ]));
    if let Some(import_modules) = res.imports {
        if !import_modules.modules.is_empty() {
            for nv in import_modules.modules.iter() {
                let functions = nv
                    .imports
                    .clone()
                    .into_iter()
                    .map(|x| x.name)
                    .collect::<Vec<_>>();
                tbl.add_row(Row::new(vec![
                    Cell::new(&nv.name),
                    Cell::new(&functions.join("\n")),
                ]));
            }
        } else {
            tbl.add_row(Row::new(vec![Cell::new_align(
                "NO DATA",
                Alignment::CENTER,
            )
            .with_hspan(2)
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::BLUE))]));
        }
    } else {
        tbl.add_row(Row::new(vec![Cell::new_align(
            "NO DATA",
            Alignment::CENTER,
        )
        .with_hspan(2)
        .with_style(Attr::Bold)
        .with_style(Attr::ForegroundColor(color::BLUE))]));
    }

    // Print the Imports table
    tbl.printstd();

    // ================= Resources table =================
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "Resources",
        Alignment::CENTER,
    )
    .with_hspan(6)
    .with_style(Attr::Bold)
    .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))]));
    tbl.add_row(Row::new(vec![
        Cell::new("Resources Type").with_style(Attr::Bold),
        Cell::new("Offset").with_style(Attr::Bold),
        Cell::new("Resource Id").with_style(Attr::Bold),
        Cell::new("Language ID").with_style(Attr::Bold),
        Cell::new("Data Start").with_style(Attr::Bold),
        Cell::new("Data End").with_style(Attr::Bold),
    ]));
    if let Some(resources) = res.resources {
        if !resources.resources.is_empty() {
            for v in resources.resources.iter() {
                let data_start = if v.data_start.is_none() {
                    "null".to_string()
                } else {
                    format!("{:#01x}", v.data_start.unwrap())
                };
                let data_end = if v.data_end.is_none() {
                    "null".to_string()
                } else {
                    format!("{:#01x}", v.data_end.unwrap())
                };
                tbl.add_row(Row::new(vec![
                    Cell::new(&v.resource_type),
                    Cell::new(&v.offset.unwrap_or(0).to_string()),
                    Cell::new(&v.resource_id),
                    Cell::new(&v.language_id),
                    Cell::new(&data_start),
                    Cell::new(&data_end),
                ]));
            }
        } else {
            tbl.add_row(Row::new(vec![Cell::new_align(
                "NO DATA",
                Alignment::CENTER,
            )
            .with_hspan(6)
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::BLUE))]));
        }
    } else {
        tbl.add_row(Row::new(vec![Cell::new_align(
            "NO DATA",
            Alignment::CENTER,
        )
        .with_hspan(6)
        .with_style(Attr::Bold)
        .with_style(Attr::ForegroundColor(color::BLUE))]));
    }

    // Print the Resources table
    tbl.printstd();

    // ================= Thread Local Storage (TLS) Callbacks =================
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "Thread Local Storage (TLS) Callbacks",
        Alignment::CENTER,
    )
    .with_hspan(2)
    .with_style(Attr::Bold)
    .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))]));
    if let Some(tls) = res.tls_callbacks {
        if !tls.callbacks.is_empty() {
            for v in tls.callbacks.iter() {
                tbl.add_row(Row::new(vec![
                    Cell::new("Address"),
                    Cell::new(&format!("{:#01x}", v)),
                ]));
            }
        } else {
            tbl.add_row(Row::new(vec![Cell::new_align(
                "NO DATA",
                Alignment::CENTER,
            )
            .with_hspan(2)
            .with_style(Attr::Bold)
            .with_style(Attr::ForegroundColor(color::BLUE))]));
        }
    } else {
        tbl.add_row(Row::new(vec![Cell::new_align(
            "NO DATA",
            Alignment::CENTER,
        )
        .with_hspan(2)
        .with_style(Attr::Bold)
        .with_style(Attr::ForegroundColor(color::BLUE))]));
    }

    // Print the Thread Local Storage (TLS) Callback table
    tbl.printstd();

    Ok(())
}
