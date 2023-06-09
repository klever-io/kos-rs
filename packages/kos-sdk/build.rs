
fn main() {
    let config = dotenv_build::Config {
        filename: std::path::Path::new(".env.nodes"),
        recursive_search: false,
        fail_if_missing_dotenv: true,
        ..Default::default()
    };
    
    dotenv_build::output(config).unwrap();
}