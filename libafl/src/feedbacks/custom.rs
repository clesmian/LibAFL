//! Custom Feedback, returning the result of a closure.
//!

use serde::{Deserialize, Serialize};
use libafl_bolts::{Error, Named};
use crate::events::EventFirer;
use crate::executors::ExitKind;
use crate::feedbacks::Feedback;
use crate::observers::ObserversTuple;
use crate::prelude::State;
use alloc::string::{String, ToString};

/// The [`CustomFeedback`] takes a closure and reports the result of executing this closure.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CustomFeedback<F>
where F: Fn() -> bool,
{
    name: String,
    is_interesting_func: F,
    last_status: bool
}

impl<S, F> Feedback<S> for CustomFeedback<F>
    where
        S: State,
        F: Fn() -> bool,
{
    #[inline]
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
        where
            EM: EventFirer<State=S>,
            OT: ObserversTuple<S>,
    {
        let current_status = (self.is_interesting_func)();
        if current_status != self.last_status {
            // Allow for individual filtering of different CustomFeedbacks
            // by supplying its name as target
            log::info!(target: &self.name,"Switching status to {}", current_status);
            self.last_status = current_status;
        }
        Ok(current_status)
    }
}

impl<F> Named for CustomFeedback<F>
where F: Fn() -> bool,{
    #[inline]
    fn name(&self) -> &str { self.name.as_str() }
}

impl<F>  CustomFeedback<F>
where F: Fn() -> bool, {
    /// Creates a new [`CustomFeedback`] with the given name and closure
    #[must_use]
    pub fn new(name: &'static str, func: F) -> Self {
        let temp = func();
        Self{
            name: name.to_string(),
            is_interesting_func: func,
            last_status: temp
        }
    }
}