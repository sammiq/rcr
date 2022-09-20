pub trait OptionExt<T> {
    fn if_some<F>(self, f: F)
    where
        F: FnOnce(T);
}

impl<T> OptionExt<T> for Option<T> {
    /// Calls a closure on a contained value of `Option<T>` if there is one, consuming the value.
    #[inline]
    fn if_some<F>(self, f: F)
    where
        F: FnOnce(T),
    {
        if let Some(x) = self {
            f(x);
        }
    }
}

pub trait ResultExt<T, E> {
    fn if_ok<F>(self, f: F)
    where
        F: FnOnce(T);

    fn if_err<F>(self, f: F)
    where
        F: FnOnce(E);
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    /// Calls a closure on a contained value `T` of `Result<T, E>` if there is one, consuming the value.
    #[inline]
    fn if_ok<F>(self, f: F)
    where
        F: FnOnce(T),
    {
        if let Ok(x) = self {
            f(x);
        }
    }

    /// Calls a closure on a contained error `E` of `Result<T, E>` if there is one, consuming the error.
    #[inline]
    fn if_err<F>(self, f: F)
    where
        F: FnOnce(E),
    {
        if let Err(e) = self {
            f(e);
        }
    }
}
