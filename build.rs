use nom::bytes::complete::take_till1;
use nom::character::complete::{hex_digit1, space1};
use nom::combinator::{map, opt};
use nom::multi::{fold_many0, many0, many1};
use nom::sequence::{delimited, preceded, terminated};
use nom::{
    bytes::complete::{tag, take_until},
    sequence::tuple,
    IResult,
};
use std::collections::HashMap;
use std::{env, path::Path};
use std::{fs::File, io::Write};

const COMPS: &str = include_str!("assets/comp_id.txt");

fn comment(input: &str) -> IResult<&str, ()> {
    let (i, _res) = terminated(opt(tuple((tag("#"), take_until("\n")))), tag("\n"))(input)?;
    Ok((i, ()))
}

fn hex_u32(input: &str) -> IResult<&str, u32> {
    map(hex_digit1, |s: &str| u32::from_str_radix(s, 16).unwrap())(input)
}

fn lang(input: &str) -> IResult<&str, &str> {
    delimited(tag("["), take_until("]"), tag("]"))(input)
}

fn desc(input: &str) -> IResult<&str, &str> {
    let re = take_till1(|c| c == '#' || c == '\n')(input);
    re
}

fn comp_id(input: &str) -> IResult<&str, HashMap<u32, &str>> {
    preceded(
        many0(comment),
        fold_many0(
            tuple((
                terminated(hex_u32, space1),
                terminated(lang, space1),
                terminated(desc, many1(comment)),
            )),
            HashMap::new,
            |mut acc, (comp_id, _lang, desc)| {
                acc.insert(comp_id, desc);
                acc
            },
        ),
    )(input)
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("comp_id.rs");
    let mut dest_file = File::create(&dest_path).unwrap();
    let (ii, comp_id_map) = comp_id(COMPS).unwrap();
    assert!(ii.is_empty());
    write!(
        dest_file,
        r###"
fn comp_ids() ->  HashMap<u32, &'static str> {{
    let mut map = HashMap::new();
"###
    )
    .unwrap();
    comp_id_map.iter().for_each(|(id, desc)| {
        write!(
            &dest_file,
            r###"
    map.insert({}, "{}");"###,
            id, desc
        )
        .unwrap();
    });

    write!(
        &dest_file,
        r###"
        map
}}
"###,
    )
    .unwrap();
    println!("cargo::rerun-if-changed=build.rs");
}
