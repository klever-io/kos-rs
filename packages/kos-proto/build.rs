use glob::glob;
use heck::CamelCase;
use prost_wkt_build::*;
use quote::{format_ident, quote};
use std::fs::{self, File, OpenOptions};
use std::io::Error;
use std::io::Write;
use std::path::Path;
use std::{env, path::PathBuf};

fn build_pbjson(
    package_name: &str,
    proto_serde: &[impl AsRef<str>],
    protos: &[impl AsRef<Path>],
    includes: &[impl AsRef<Path>],
    use_number_for_ui64: bool,
    use_hex_for_bytes: bool,
    btree_map: bool,
) -> Result<(), Error> {
    let full_path = format!("{}/{}", env::var("OUT_DIR").unwrap().as_str(), package_name);
    fs::create_dir_all(&full_path).unwrap();

    let out_dir = PathBuf::from(&full_path);
    let descriptor_file = out_dir.join(format!("{}.descriptors.bin", package_name));
    let mut prost_build = prost_build::Config::new();
    prost_build
        .extern_path(".google.protobuf", "::pbjson_types")
        .file_descriptor_set_path(&descriptor_file)
        .protoc_arg("--experimental_allow_proto3_optional")
        // Override prost-types with pbjson-types
        .compile_well_known_types();

    if btree_map {
        prost_build.btree_map(["."]);
    }

    prost_build
        .out_dir(&full_path)
        .compile_protos(protos, includes)
        .unwrap();

    let descriptor_bytes = std::fs::read(descriptor_file).unwrap();

    let descriptor = FileDescriptorSet::decode(&descriptor_bytes[..]).unwrap();

    let mut binding = pbjson_build::Builder::new();
    binding
        .preserve_proto_field_names()
        .register_descriptors(&descriptor_bytes)?
        .use_number_for_ui64(use_number_for_ui64)
        .use_hex_for_bytes(use_hex_for_bytes);

    if btree_map {
        binding.btree_map(["."]);
    }

    binding.out_dir(&full_path).build(proto_serde)?;

    generate_extras(&out_dir, &descriptor);

    println!("cargo:warning={}", full_path);

    Ok(())
}

fn get_files(dir: &str) -> Vec<String> {
    let mut list: Vec<String> = vec![];
    for entry in glob(dir).expect("Failed to read glob pattern") {
        if let Ok(st) = entry {
            list.push(format!("./{:}", st.display()));
        }
    }
    list
}

#[allow(dead_code)]
fn build_prost_serde(
    package_name: &str,
    protos: &[impl AsRef<Path>],
    includes: &[impl AsRef<Path>],
) -> Result<(), Error> {
    let full_path = format!("{}/{}", env::var("OUT_DIR").unwrap().as_str(), package_name);
    fs::create_dir_all(&full_path).unwrap();

    let out_dir = PathBuf::from(&full_path);
    let descriptor_file = out_dir.join(format!("{}.descriptors.bin", package_name));
    let mut prost_build = prost_build::Config::new();
    prost_build
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .compile_well_known_types()
        .extern_path(".google.protobuf.Any", "::prost_wkt_types::Any")
        .extern_path(".google.protobuf.Timestamp", "::prost_wkt_types::Timestamp")
        .extern_path(".google.protobuf.Value", "::prost_wkt_types::Value")
        .out_dir(&out_dir)
        .file_descriptor_set_path(&descriptor_file)
        .compile_protos(protos, includes)?;

    let descriptor_bytes = std::fs::read(descriptor_file)?;

    let descriptor = FileDescriptorSet::decode(&descriptor_bytes[..])?;

    prost_wkt_build::add_serde(out_dir, descriptor);

    println!("cargo:warning={}", full_path);

    Ok(())
}

fn main() -> Result<(), Error> {
    // kleverchain
    build_pbjson(
        "klever",
        &[".proto"],
        get_files("proto/klever/*.proto").as_slice(),
        &["proto/klever"],
        true,
        false,
        false,
    )?;

    // Tron protocol
    let mut list = get_files("proto/tron/core/contract/*.proto");
    list.push("proto/tron/core/Tron.proto".to_string());
    list.push("proto/tron/core/Discover.proto".to_string());
    list.push("proto/tron/api/api.proto".to_string());

    build_pbjson(
        "tron",
        &[".protocol"],
        list.as_slice(),
        &["proto/include", "proto/tron"],
        true,
        true,
        false,
    )?;

    Ok(())
}

fn generate_extras(out_dir: &Path, file_descriptor_set: &FileDescriptorSet) {
    for fd in &file_descriptor_set.file {
        let package = match fd.package {
            Some(ref pkg) => pkg,
            None => continue,
        };

        if package.starts_with("google.") {
            continue;
        }

        let gen_path = out_dir.join(format!("{}.rs", package));
        let mut gen_file = OpenOptions::new().append(true).open(gen_path).unwrap();

        for msg in &fd.message_type {
            let name = match msg.name {
                Some(ref name) => name,
                None => continue,
            };

            let type_url = format!("type.googleapis.com/{}.{}", package, name);
            let type_name = name.to_camel_case();

            gen_type_url(&mut gen_file, &type_url, &type_name);
        }
    }
}

fn gen_type_url(gen_file: &mut File, type_url: &str, type_name: &str) {
    let type_name = format_ident!("{}", type_name);

    let tokens = quote! {
        impl crate::TypeUrl for #type_name {
            fn type_url() -> &'static str {
                #type_url
            }
        }
    };

    writeln!(gen_file).unwrap();
    writeln!(gen_file, "{}", &tokens).unwrap();
}
