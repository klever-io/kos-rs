use heck::CamelCase;
use prost_wkt_build::*;
use quote::{format_ident, quote};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::{env, path::PathBuf};

fn build_pbjson(pacakge_name: &str, protos: &[impl AsRef<Path>], includes: &[impl AsRef<Path>]) {
    let full_path = format!("{}/{}", env::var("OUT_DIR").unwrap().as_str(), pacakge_name);
    fs::create_dir_all(&full_path).unwrap();

    let out_dir = PathBuf::from(&full_path);
    let descriptor_file = out_dir.join("descriptors.bin");
    let mut prost_build = prost_build::Config::new();
    prost_build
        .extern_path(".google.protobuf", "::pbjson_types")
        .file_descriptor_set_path(&descriptor_file)
        .protoc_arg("--experimental_allow_proto3_optional")
        // Override prost-types with pbjson-types
        .compile_well_known_types()
        .out_dir(&full_path)
        .compile_protos(protos, includes)
        .unwrap();

    let descriptor_bytes = std::fs::read(descriptor_file).unwrap();

    let descriptor = FileDescriptorSet::decode(&descriptor_bytes[..]).unwrap();

    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_bytes)
        .unwrap()
        .out_dir(&full_path)
        .build(&[".proto"])
        .unwrap();

    generate_extras(&out_dir, &descriptor);
}

fn main() {
    // kleverchain
    build_pbjson(
        "klever",
        &[
            "proto/klever/transaction.proto",
            "proto/klever/contracts.proto",
            "proto/klever/userAccountData.proto",
        ],
        &["proto/klever"],
    );

    // Tron protocol
    build_pbjson(
        "tron",
        &["proto/tron/core/Tron.proto", "proto/tron/api/api.proto"],
        &["proto/include", "proto/tron"],
    );
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
