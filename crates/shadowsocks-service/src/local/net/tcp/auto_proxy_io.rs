//! Trait of auto-proxy I/O

/// Proxy I/O chooses Direct or Proxy automatically
pub trait AutoProxyIo {
    /// Check if the current connection uses Proxy
    fn is_proxied(&self) -> bool;

    /// Check if the current connection uses Direct
    fn is_bypassed(&self) -> bool {
        !self.is_proxied()
    }
}
