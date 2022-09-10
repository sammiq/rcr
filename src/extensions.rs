pub trait IfSome<T> {
    fn if_some<F>(self, f: F)
    where
        F: FnOnce(T);
}

impl<T> IfSome<T> for Option<T> {
    /// Calls a closure on a contained value of `Option<T>` if there is one, consuming the value.
    #[inline]
    fn if_some<F>(self, f: F)
    where
        F: FnOnce(T),
    {
        match self {
            Some(x) => f(x),
            None => (),
        }
    }
}
