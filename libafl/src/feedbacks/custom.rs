//! Custom Feedback, returning the result of a closure.
//!

use serde::{Deserialize, Serialize};
use libafl_bolts::{Error, Named};
use crate::events::EventFirer;
use crate::executors::ExitKind;
use crate::feedbacks::Feedback;
use crate::observers::ObserversTuple;
use crate::prelude::{HasNamedMetadata, State};
use alloc::string::{String, ToString};
use std::marker::PhantomData;

/// The [`CustomFeedback`] takes a closure and reports the result of executing this closure.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CustomFeedback<'a, F, S>
    where
        S: State + HasNamedMetadata,
        F: Fn(&mut S) -> bool,
{
    name: String,
    is_interesting_func: F,
    last_status: Option<bool>,
    _state: PhantomData<&'a S>
}

impl<F, S> Feedback<S> for CustomFeedback<'_, F, S>
    where
        F: Fn(&mut S) -> bool,
        S: State + HasNamedMetadata
{
    #[inline]
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
        where
            EM: EventFirer<State=S>,
            OT: ObserversTuple<S>,
    {
        let current_status = (self.is_interesting_func)(state);
        if !self.last_status.is_some_and(|last| -> bool {last == current_status}) {
            // Allow for individual filtering of different CustomFeedbacks
            // by supplying its name as target
            log::info!("{}: Switching status to {}", &self.name, current_status);
            self.last_status = Some(current_status);
        }
        Ok(current_status)
    }
}

impl<F, S> Named for CustomFeedback<'_, F, S>
    where
        F: Fn(&mut S) -> bool,
        S: State + HasNamedMetadata
{
    #[inline]
    fn name(&self) -> &str { self.name.as_str() }
}

impl<F, S>  CustomFeedback<'_, F, S>
    where
        F: Fn(&mut S) -> bool,
        S: State + HasNamedMetadata
{
    /// Creates a new [`CustomFeedback`] with the given name and closure
    #[must_use]
    pub fn new(name: &'static str, func: F) -> Self {
        Self{
            name: name.to_string(),
            is_interesting_func: func,
            last_status: None,
            _state: PhantomData::default()
        }
    }
}