/// Converts cindy errors into `anyhow` ones, keeping the cause chain.
///
/// `?` can't do it: both error types are foreign to each other's
/// crates, so the `From` impl that would make it work can't live in
/// cindy, and neither type implements `std::error::Error` for
/// `anyhow`'s blanket conversion to pick up.
///
/// ```ignore
/// use cindy::IntoAnyhow;
///
/// fn tool() -> anyhow::Result<String> {
///     let value = my_playbook::lookup().into_anyhow()?;
///     Ok(value)
/// }
/// ```
pub trait IntoAnyhow {
    type Output;

    fn into_anyhow(self) -> Self::Output;
}

impl IntoAnyhow for crate::Error {
    type Output = anyhow::Error;

    fn into_anyhow(self) -> anyhow::Error {
        anyhow::Error::from_boxed(self.into())
    }
}

impl<T> IntoAnyhow for crate::Result<T> {
    type Output = anyhow::Result<T>;

    fn into_anyhow(self) -> anyhow::Result<T> {
        self.map_err(IntoAnyhow::into_anyhow)
    }
}

#[cfg(test)]
mod tests {
    use super::IntoAnyhow;
    use crate::Context;

    fn failing() -> crate::Result<()> {
        Err(std::io::Error::other("disk on fire")).context("writing the config")
    }

    #[test]
    fn question_mark_works_and_the_chain_survives() {
        fn tool() -> anyhow::Result<()> {
            failing().into_anyhow()?;
            Ok(())
        }
        let err = tool().unwrap_err();
        let chain: Vec<String> = err.chain().map(ToString::to_string).collect();
        assert_eq!(chain, ["writing the config", "disk on fire"]);
        assert_eq!(format!("{err:#}"), "writing the config: disk on fire");
    }

    #[test]
    fn ok_passes_through() {
        assert_eq!(crate::Result::Ok(7).into_anyhow().unwrap(), 7);
    }
}
