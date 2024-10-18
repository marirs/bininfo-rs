use file_info::Result;

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        eprintln!("Usage:\n\t{} <file>", argv[0]);
        return Ok(());
    }
    let res = file_info::get_file_extended_information(&argv[1])?;
    eprintln!("{:?}", res);
    Ok(())
}
