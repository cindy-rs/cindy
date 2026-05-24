pub trait ConditionalSudoCommand {
    fn conditional_sudo_command<'a>(
        &'a self,
        sudo: bool,
        command: &str,
    ) -> openssh::OwningCommand<&'a openssh::Session>;
}
impl ConditionalSudoCommand for openssh::Session {
    fn conditional_sudo_command<'a>(
        &'a self,
        sudo: bool,
        command: &str,
    ) -> openssh::OwningCommand<&'a openssh::Session> {
        if sudo {
            let mut c = self.command("sudo");
            // `-n` (non-interactive): never try to read a password from the
            // tty. cindy relies on passwordless sudo, and there is no tty on
            // the remote anyway. Without `-n`, sudo on a password-requiring
            // host writes its prompt straight to the controlling terminal —
            // corrupting our alternate-screen TUI — and then blocks/fails
            // confusingly. With `-n` it instead exits fast, printing
            // `sudo: a password is required` to stderr, which we capture and
            // show in the host's output pane.
            c.arg("-n");
            c.arg(command);
            c
        } else {
            self.command(command)
        }
    }
}
