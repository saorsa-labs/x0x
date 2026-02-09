//! Event system for Python bindings.
//!
//! Provides callback registration and event dispatch for network events,
//! task updates, and other async notifications from the x0x runtime.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Event callback storage.
///
/// Stores Python callable objects that are invoked when events occur.
/// Thread-safe storage using Arc<Mutex<>> for access from both Python and Rust threads.
#[derive(Clone)]
pub struct EventCallbacks {
    /// Map of event name -> list of Python callbacks.
    /// Each callback is a PyObject that must be called with Python GIL held.
    callbacks: Arc<Mutex<HashMap<String, Vec<PyObject>>>>,
}

impl EventCallbacks {
    /// Create a new empty event callback registry.
    pub fn new() -> Self {
        Self {
            callbacks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a callback for an event.
    ///
    /// The callback will be stored and invoked whenever the event is emitted.
    ///
    /// # Arguments
    ///
    /// * `event` - Event name (e.g., "connected", "peer_joined")
    /// * `callback` - Python callable object
    pub fn register(&self, event: String, callback: PyObject) {
        let mut callbacks = self
            .callbacks
            .lock()
            .expect("EventCallbacks mutex poisoned");
        callbacks.entry(event).or_default().push(callback);
    }

    /// Remove a callback for an event.
    ///
    /// If the callback was registered multiple times, only the first occurrence is removed.
    ///
    /// # Arguments
    ///
    /// * `event` - Event name
    /// * `callback` - Python callable to remove
    ///
    /// # Returns
    ///
    /// true if a callback was removed, false if not found
    pub fn remove(&self, py: Python<'_>, event: &str, callback: &PyObject) -> bool {
        let mut callbacks = self
            .callbacks
            .lock()
            .expect("EventCallbacks mutex poisoned");

        if let Some(event_callbacks) = callbacks.get_mut(event) {
            // Find the callback by comparing PyObject equality
            if let Some(pos) = event_callbacks
                .iter()
                .position(|cb| cb.as_ref(py).is(callback.as_ref(py)))
            {
                event_callbacks.remove(pos);
                return true;
            }
        }

        false
    }

    /// Emit an event to all registered callbacks.
    ///
    /// Calls each registered callback with the event data.
    ///
    /// # Arguments
    ///
    /// * `py` - Python GIL token
    /// * `event` - Event name
    /// * `data` - Event data as Python dict
    ///
    /// # Note
    ///
    /// This method requires the GIL to be held. If any callback raises an exception,
    /// it will be printed but not propagated (to prevent one bad callback from
    /// breaking others).
    #[allow(dead_code)] // Will be used when event dispatch is implemented
    pub fn emit(&self, py: Python<'_>, event: &str, data: &PyDict) -> PyResult<()> {
        let callbacks = self
            .callbacks
            .lock()
            .expect("EventCallbacks mutex poisoned");

        if let Some(event_callbacks) = callbacks.get(event) {
            for callback in event_callbacks {
                // Call the callback with the event data
                // If it fails, print the error but continue to other callbacks
                if let Err(e) = callback.call1(py, (data,)) {
                    eprintln!("Error in event callback for '{event}': {e}");
                    e.print(py);
                }
            }
        }

        Ok(())
    }

    /// Get the number of callbacks registered for an event.
    ///
    /// Useful for testing and debugging.
    #[allow(dead_code)] // Used in unit tests
    pub fn callback_count(&self, event: &str) -> usize {
        let callbacks = self
            .callbacks
            .lock()
            .expect("EventCallbacks mutex poisoned");
        callbacks.get(event).map_or(0, |cbs| cbs.len())
    }

    /// Remove all callbacks.
    ///
    /// Useful for cleanup and testing.
    #[allow(dead_code)] // Used in unit tests
    pub fn clear(&self) {
        let mut callbacks = self
            .callbacks
            .lock()
            .expect("EventCallbacks mutex poisoned");
        callbacks.clear();
    }
}

impl Default for EventCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

// Note: Rust unit tests for this module are difficult due to PyO3's
// requirement for Python runtime initialization. All functionality is
// thoroughly tested via Python pytest tests in tests/test_events.py.
