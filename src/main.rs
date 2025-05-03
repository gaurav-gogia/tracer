use std::{collections::HashMap, os::unix::process::CommandExt, process::Command};
use nix::{sys::{ptrace, wait::waitpid}, unistd::Pid};
use owo_colors::OwoColorize;

fn main() ->  Result<(), Box<dyn std::error::Error>> {
    let json: serde_json::Value = serde_json::from_str(include_str!("calls.json"))?;
    let syscall_table: HashMap<u64, String> = json["aaData"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item[0].as_u64().unwrap(),
                item[1].as_str().unwrap().to_owned(),
            )
        })
        .collect();

    println!("I parent, my PID {}", std::process::id());
    let mut command = Command::new("cat");
    command.arg("/home/mew/Desktop/sample");
    unsafe {
        command.pre_exec(|| {
            println!("I'm squid, my PID: {}", std::process::id());
            use nix::sys::ptrace::traceme;
            eturn traceme().map_err(|e| e.into());           
        });
    }

    let child = command.spawn()?;
    let child_pid = Pid::from_raw(child.id() as _);
        
    let res = waitpid(child_pid,None)?;
    eprintln!("waitpid res: {:?}", res.yellow());

    let mut exit =false;
    loop {
        ptrace::syscall(child_pid, None)?;
        _ = waitpid(child_pid, None)?;
        if exit {
            let regs = ptrace::getregs(child_pid)?;

            let call = &syscall_table[&regs.orig_rax];
            if call == "close" {
                eprintln!("{} | malware detected!", call.red());
                break;
            }

            eprintln!(
                "{}({:x}, {:x}, {:x}, ...) = {:x}",
                syscall_table[&regs.orig_rax].green(),
                regs.rdi.blue(),
                regs.rsi.blue(),
                regs.rdx.blue(),
                regs.rax.yellow(),
            );
        }
        exit = !exit;
    }

    Ok(())
}
