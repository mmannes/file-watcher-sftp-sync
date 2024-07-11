use std::{path::Path, time::Duration};
use std::ffi::OsStr;

use notify::RecursiveMode;
use notify_debouncer_mini::new_debouncer;

use std::io::prelude::*;

use std::net::TcpStream;
use ssh2::Session;

use std::{fs, thread};
use std::env;
use crate::RemoteSync::*;

mod config;

const CONFIG_FILE: &str = "file-sync.toml";
fn send_or_remove_file(config: &config::Config, mut sess: Session, file: &Path) -> Result<Session, &'static str> {
    match fs::read(file) {
        Ok(local_file) => {
            print!(", sending ");
            send_file(&config, sess, &file, local_file)
        },
        Err(_) => {
            print!(", removing ");
            remove_file_from_remote(&config, sess, &file)
        }
    }
}

fn remove_file_from_remote(config: &config::Config, mut sess: Session, file: &Path) -> Result<Session, &'static str> {
    let config_path = &config.remote_server.as_ref().unwrap().path.clone();
    let remote_path = Path::new(config_path);
    let current_dir = env::current_dir().unwrap();
    let relative_path = file.strip_prefix(current_dir);
    if relative_path.is_err(){
        // relative_path being an Err means that we tried to get the parent directory above the
        // directory we are listening
        return Err("Failed trying to create the path to file in the remote server")
    }
    let relative_dir = relative_path.unwrap();
    let remote_file = remote_path.join(relative_dir);
    print!("from remote destination: '{}'... ", remote_file.display());
    let sftp = sess.sftp();
    match sftp {
        Ok(sftp) => {
            match sftp.unlink(&remote_file) {
                Ok(_) => {
                    print!("OK\r\n");
                    Ok(sess)
                },
                Err(_) => Err("Failed to remove file from remote server.")
            }
        },
        Err(_) => Err("Failed to open sftp session.")
    }
}

fn send_file(config: &config::Config, mut sess: Session, file: &Path, local_file: Vec<u8>) -> Result<Session, &'static str> {
    let file_size: u64 = local_file.len().try_into().unwrap();
    let config_path = &config.remote_server.as_ref().unwrap().path.clone();
    let remote_path = Path::new(config_path);
    let current_dir = env::current_dir().unwrap();
    let relative_path = file.strip_prefix(current_dir);
    if relative_path.is_err(){
        // relative_path being an Err means that we tried to get the parent directory above the
        // directory we are listening
        return Err("Failed trying to create the path to file in the remote server")
    }
    let relative_dir = relative_path.unwrap();
    let remote_file = remote_path.join(relative_dir);
    let relative_dir_to_run_test = relative_dir.clone();
    print!("to remote destination: '{}'... ", remote_file.display());
    let channel = sess.scp_send(remote_file.as_path(),
                                        0o644, file_size, None);
    match channel {
        Ok(mut remote_file) => {
            remote_file.write_all(&local_file).unwrap();
            // Close the channel and wait for the whole content to be transfered
            remote_file.send_eof().unwrap();
            remote_file.wait_eof().unwrap();
            remote_file.close().unwrap();
            remote_file.wait_close().unwrap();
            print!("OK\r\n");
            run_test(&config, &relative_dir_to_run_test);
            Ok(sess)
        },
        Err(error) => {
            print!("\r\n");
            match error.code() {
                ssh2::ErrorCode::Session(i) => {
                    if i == -7 {
                        print!(" (disconnected ");
                        sess = connect(&config);
                        print!("connected) ");
                        print_apache2_error_log(&config);
                        return send_or_remove_file(&config, sess, &file);
                    } else {
                        println!("Session error with code {}", i);
                    }
                },
                ssh2::ErrorCode::SFTP(i) => println!("Sftp error with code {}", i),
            }
            // try to get the parent directory and then try to send it again
            let sftp = sess.sftp();
            match sftp {
                Ok(sftp) => {
                    for component in relative_dir.components() {
                        if component.as_os_str() == remote_file.file_name().unwrap() {
                            // stops trying to create directories when the component is the file
                            break;
                        }
                        let dir_to_be_created = &remote_path.join(Path::new(&component));
                        print!("Trying to create directory '{}'... ", dir_to_be_created.display());
                        if sftp.mkdir(&dir_to_be_created, 0o744).is_err() {
                            print!("FAILED!\r\n");
                            return Err("Failed while trying to create remote directory");
                        }
                        print!("created.\r\n");
                    };
                    print!("Trying to send again with parent directories created... ");
                    let channel = sess.scp_send(remote_file.as_path(),
                                                        0o644, file_size, None);
                    match channel {
                        Ok(mut remote_file) => {
                            remote_file.write_all(&local_file).unwrap();
                            // Close the channel and wait for the whole content to be transfered
                            remote_file.send_eof().unwrap();
                            remote_file.wait_eof().unwrap();
                            remote_file.close().unwrap();
                            remote_file.wait_close().unwrap();
                            print!("OK\r\n");
                            run_test(&config, &relative_dir_to_run_test);
                            Ok(sess)
                        },
                        Err(_) => Err("Failed when trying to send file after creating its path, probably there is a permission problem.")
                    }
                },
                Err(_) => Err("Failed to open sftp session.")
            }
        }
    }
}

fn connect(config: &config::Config) -> ssh2::Session {
    let mut sess = Session::new().unwrap();
    let tcp = TcpStream::connect(get_remote_address(&config)).unwrap();
    sess.set_tcp_stream(tcp);
    match sess.handshake() {
        Ok(_) => (),
        Err(s) => {
            panic!("ERROR WHILE HANDSHAKE: {:?}", s);
        }
    }
    match sess.userauth_password(get_remote_username(&config), get_remote_password(&config)) {
        Ok(_) => (),
        Err(s) => panic!("AUTHENTICATION ERROR: {:?}", s),
    };
    if sess.authenticated() {
        println!("Authenticated on remote host.");
    } else {
        println!("Authentication failed!");
    }
    return sess
}

fn run_test(config: &config::Config, filename: &Path) {
    //todo!("validate the filename based on regex or other clever rule");
    if filename.file_name().unwrap().to_str().unwrap().get(0..5).unwrap() != "test_" || filename.extension().unwrap().to_str() != Some("php") {
        return;
    }
    println!("It's a test, running... ");
    let sess = connect(&config);
    let mut channel = sess.channel_session().unwrap();
    //todo!("create a config inside .toml file in order to execute some command, filename should be a variable to that command.");
    let mut command = String::from("sudo docker exec development-docker-amd64-webserver-1 sh -c \"php -c /etc/php/5.6/apache2 /media/www/");
    command.push_str(filename.to_str().unwrap());
    command.push_str("\"");
    println!("{}", &command);
    channel.exec(&command).unwrap();
    //let mut s = String::new();
    //channel.read_to_string(&mut s).unwrap();
    let mut buffer: Vec<u8> = Vec::new();
    channel.read_to_end(&mut buffer).unwrap();
    let s = match std::str::from_utf8(&buffer[..]) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    print!("{}", s);
    match channel.close() {
        Ok(_) => (),
        Err(_) => println!("Failed closing channel after running test."),
    };
}

fn print_apache2_error_log(config: &config::Config) -> thread::JoinHandle<()> {
    //todo!("criar configuração para executar comando ao iniciar uma conexão com o servidor.");
    let cloned_config = config.clone();
    thread::spawn(move || {
        let sess = connect(&cloned_config);
        let mut channel = sess.channel_session().unwrap();
        channel.exec("tail -f -n 0 ~/media/log/error.log").unwrap();
        let mut buffer = [0; 256];
        while let Ok(n) = channel.read(&mut buffer[..]) {
            let s = match std::str::from_utf8(&buffer[..n]) {
                Ok(v) => v,
                Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            };
            print!("{}", s);
        };
    })
}

fn load_config(config_file: &str) -> Result<config::Config, String> {
    // look for file-sync.toml
    if let Ok(contents) = fs::read(config_file) {
        println!("{} has been read.", config_file);
        match toml::from_slice(&contents) {
            Ok(t) => Ok(t),
            Err(e) => Err(e.to_string()),
        }
    } else {
        panic!("There must be a \"{}\" file in the same directory as the executable", config_file);
    }
}

#[test]
fn test_example_config() {
    let env_var_cargo_manifest_dir = "CARGO_MANIFEST_DIR";
    if let Ok(cargo_manifest_dir) = env::var(env_var_cargo_manifest_dir) {
        let sample_config_file = format!("{}/{}", cargo_manifest_dir, "file-sync-example.toml");
        println!("Sample config file: {}", &sample_config_file);
        let config = load_config(&sample_config_file);
        assert_eq!(
            format!("{:?}", config), 
            "Ok(Config { remote_server: RemoteServer { address: \"192.168.1.1:22\", user: \"your_user_name\", password: Some(\"your_password\"), path: \"/home/your_user_name/some_dir/\", allowed_extensions: Some([\"php\", \"html\", \"css\", \"js\", \"rs\"]) } })"
        );
    } else {
        panic!("{}", format!("Failed to read local environment variable {}.", &env_var_cargo_manifest_dir));
    }
}

fn has_remote_server(config: &config::Config) -> bool {
    match &config.remote_server {
        Some(_) => true,
        None => false,
    }
}

fn get_remote_username(config: &config::Config) -> &String {
    &config.remote_server.as_ref().unwrap().user
}

fn get_remote_password(config: &config::Config) -> &String {
    &config.remote_server.as_ref().unwrap().password.as_ref().unwrap()
}

fn get_remote_address(config: &config::Config) -> &String {
    &config.remote_server.as_ref().unwrap().address
}

pub enum RemoteSync {
    Enabled(ssh2::Session),
    Disabled,
}

fn main() {
    let config = match load_config(CONFIG_FILE) {
        Ok(c) => c,
        Err(e) => panic!("{}", e),
    };

    let mut remote_sync = RemoteSync::Disabled;

    if has_remote_server(&config) {
        remote_sync = RemoteSync::Enabled(connect(&config));
    }

    let _read_logs = print_apache2_error_log(&config);

    // setup debouncer
    let (tx, rx) = std::sync::mpsc::channel();

    let mut debouncer = new_debouncer(Duration::from_millis(config.debounce_timeout.clone()), None, tx).unwrap();

    debouncer
        .watcher()
        .watch(Path::new("./"), RecursiveMode::Recursive)
        .unwrap();

    //let allowed_extensions = vec!["php", "html", "css", "js", "rs", "xml"];
    let mut allowed_extensions = vec![];
    match &config.remote_server {
        Some(remote_server) => match &remote_server.allowed_extensions {
            Some(v) => {
                for extension in v {
                    allowed_extensions.push(extension.clone());
                }
            },
            None => {},
        },
        None => {},
    };

    // loop all events, non returning
    for events in rx {
        for e in events { 
            for event in e { 
                let file_path = Path::new(&event.path); 
                let file_extension = String::from(file_path.extension().unwrap_or(OsStr::new("")).to_str().unwrap());
                let file_name = file_path.file_name().unwrap_or(OsStr::new(""));
                if allowed_extensions.is_empty() || allowed_extensions.contains(&file_extension) { 
                    print!("File {:?} has changed", &file_name);
                    remote_sync = match remote_sync {
                        Enabled(sess) => {
                            let modified_session = match send_or_remove_file(&config, sess, &file_path) {
                                Ok(session) => {
                                    session
                                },
                                Err(s) => {
                                    panic!("FAILED: {:?}", s);
                                },
                            };
                            RemoteSync::Enabled(modified_session)
                        },
                        Disabled => {
                            println!(".");
                            RemoteSync::Disabled
                        },
                    };
                }
            }
            //let extension = e.path.extension();
            //assert_eq!(extension, Some(OsStr::new("txt")));
        }
    }
}
