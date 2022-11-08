use std::{path::Path, time::Duration};
use std::ffi::OsStr;

use notify::{RecursiveMode};
use notify_debouncer_mini::new_debouncer;

use std::io::prelude::*;
use std::net::TcpStream;
use ssh2::{Session};

use std::fs;
use std::env;

fn connect_to_ssh_host(tcp: TcpStream, mut sess: Session) -> Session {
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    sess.userauth_password("extranetdev", "53CiVm8zG7DmKS").unwrap();
    if sess.authenticated() {
        println!("Authenticated on remote host.");
    } else {
        println!("AUTHENTICATION ON REMOTE HOST FAILED!");
    }
    sess
}

fn send_file(sess: &Session, file: &Path) -> Result<(), &'static str> {
    let local_file = fs::read(file).unwrap();
    let file_size: u64 = local_file.len().try_into().unwrap();
    let remote_path = Path::new("/home/extranetdev/media/www/");
    let current_dir = env::current_dir().unwrap();
    let relative_path = file.strip_prefix(current_dir);
    if relative_path.is_err(){
        // relative_path being an Err means that we tried to get the parent directory above the
        // directory we are listening
        return Err("Failed trying to create the path to file in the remote server")
    }
    let relative_dir = relative_path.unwrap();
    let remote_file = remote_path.join(relative_dir);
    print!("to remote destination: '{}'... ", remote_file.display());
    let channel = sess.scp_send(remote_file.as_path(),
                                        0o644, file_size, None);
    match channel {
        Ok(mut remote_file) => {
            remote_file.write(&local_file).unwrap();
            // Close the channel and wait for the whole content to be transfered
            remote_file.send_eof().unwrap();
            remote_file.wait_eof().unwrap();
            remote_file.close().unwrap();
            remote_file.wait_close().unwrap();
            print!("OK\r\n");
            Ok(())
        },
        Err(_) => {
            print!("\r\n");
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
                            remote_file.write(&local_file).unwrap();
                            // Close the channel and wait for the whole content to be transfered
                            remote_file.send_eof().unwrap();
                            remote_file.wait_eof().unwrap();
                            remote_file.close().unwrap();
                            remote_file.wait_close().unwrap();
                            print!("OK\r\n");
                            Ok(())
                        },
                        Err(_) => Err("Failed when trying to send file after creating its path, probably there is a permission problem.")
                    }
                },
                Err(_) => Err("Failed to open sftp session.")
            }
        }
    }
}


/// Example for debouncer
fn main() {
    let mut sess = Session::new().unwrap();
    let tcp = TcpStream::connect("192.168.99.192:22").unwrap();
    sess = connect_to_ssh_host(tcp, sess);

    // setup debouncer
    let (tx, rx) = std::sync::mpsc::channel();

    // No specific tickrate, max debounce time 2 seconds
    let mut debouncer = new_debouncer(Duration::from_millis(100), None, tx).unwrap();

    debouncer
        .watcher()
        .watch(Path::new("./"), RecursiveMode::Recursive)
        .unwrap();

    let allowed_extensions = vec!["php", "html", "css", "js", "rs"];

    // loop all events, non returning
    for events in rx {
        for e in events {
            for event in e {
                let file_path = Path::new(&event.path);
                let file_extension = file_path.extension().unwrap_or(OsStr::new(""));
                if allowed_extensions.contains(&file_extension.to_str().unwrap_or("")) {
                    print!("File {:?} change detected, sending ", &file_path.file_name().unwrap_or(OsStr::new("")));
                    match send_file(&sess, &file_path) {
                        Ok(()) => print!(""),
                        Err(s) => print!("ERROR: {}\r\n", s),
                    }
                }
            }
            //let extension = e.path.extension();
            //assert_eq!(extension, Some(OsStr::new("txt")));
            }
        }
    }
