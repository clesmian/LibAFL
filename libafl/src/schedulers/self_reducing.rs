use libafl_bolts::{AsSlice, Error};
use crate::corpus::{Corpus, CorpusId, Testcase};
use crate::inputs::UsesInput;
use crate::observers::ObserversTuple;
use crate::prelude::{HasCorpus, HasMetadata, HasRand, RemovableScheduler, Scheduler, UsesState};


use alloc::{collections::vec_deque::VecDeque, vec::Vec};
use std::collections::HashMap;
use std::ops::Deref;
use log::{debug, error};
use crate::feedbacks::MapIndexesMetadata;

/// The [`CorpusLimitingScheduler`]
#[derive(Debug, Clone)]
pub struct CorpusLimitingScheduler<CS> {
    base: CS,
    max_test_cases_with_same_code_cov: usize,
    code_cov_maps: HashMap<Vec<usize>, VecDeque<CorpusId>>,
}

// #[cfg(feature = "std")]
// #[derive(Default, Serialize, Deserialize, Clone, Debug)]
// pub struct CorpusLimitingSchedulerMetadata {
//     max_test_cases_with_same_code_cov: usize,
//     code_cov_maps: HashMap<Vec<usize>, VecDeque<CorpusId>>,
// }
//
// impl_serdeany!(CorpusLimitingSchedulerMetadata);

impl<CS> UsesState for CorpusLimitingScheduler<CS>
    where
        CS: UsesState,
{
    type State = CS::State;
}

impl<CS> RemovableScheduler for CorpusLimitingScheduler<CS>
    where
        CS: RemovableScheduler,
        CS::State: HasCorpus + HasMetadata + HasRand,
{
    /// Removes an entry from the corpus
    fn on_remove(
        &mut self,
        state: &mut CS::State,
        idx: CorpusId,
        testcase: &Option<Testcase<<CS::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        // TODO: Should we ensure that the test case is not referenced anywhere anymore?
        self.base.on_remove(state, idx, testcase)
    }

    /// Replaces the testcase at the given idx
    fn on_replace(
        &mut self,
        state: &mut CS::State,
        idx: CorpusId,
        testcase: &Testcase<<CS::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        self.base.on_replace(state, idx, testcase)
    }
}

impl<CS> Scheduler for CorpusLimitingScheduler<CS>
    where
        CS: Scheduler + RemovableScheduler,
        CS::State: HasCorpus + HasMetadata + HasRand,
{
    /// Called when a [`Testcase`] is added to the corpus
    fn on_add(&mut self, state: &mut CS::State, idx: CorpusId) -> Result<(), Error> {
        // TODO Add check for existing test cases with same code coverage

        let mut meta_as_vec = None;

        if let Ok(meta) = state.corpus().get(idx)?.borrow().metadata::<MapIndexesMetadata>() {
            meta_as_vec = Some(Vec::from(meta.as_slice()));
        }
        if let Some(meta_as_vec) = meta_as_vec{
            if let Some(test_cases) = self.code_cov_maps.get_mut(&meta_as_vec){
                debug!("We know {} testcases with the same code coverage", test_cases.len());
                while test_cases.len() >= self.max_test_cases_with_same_code_cov {
                    // TODO Is there a more useful strategy?
                    let to_remove = test_cases.pop_back();
                    debug!("Removing test case {:?}", to_remove);
                    let testcase_to_remove = state.corpus().get(idx)?.borrow().deref();
                    if let Err(e) = self.base.on_remove(state, to_remove.unwrap(), &Some(testcase_to_remove.clone())){
                        error!("base.on_remove was unsuccessful: {}", e);
                    }
                    if let Err(e) = state.corpus_mut().remove(idx){
                        error!("corpus.remove was unsuccessful: {}", e);
                    }
                }
            } else {
                self.code_cov_maps.insert(meta_as_vec.clone(), VecDeque::from([]));
            }
            self.code_cov_maps.get_mut(&meta_as_vec).unwrap().push_front(idx);
        } else {
            return Err(
                Error::NotImplemented(
                    "Cannot add test case as there is no MapIndexesMetadata for testcase".parse().unwrap(),
                    Default::default()
                )
            )
        }

        self.base.on_add(state, idx)
    }

    /// An input has been evaluated
    fn on_evaluation<OT>(
        &mut self,
        state: &mut Self::State,
        input: &<Self::State as UsesInput>::Input,
        observers: &OT,
    ) -> Result<(), Error>
        where
            OT: ObserversTuple<Self::State>,
    {
        self.base.on_evaluation(state, input, observers)
    }

    /// Gets the next entry
    fn next(&mut self, state: &mut CS::State) -> Result<CorpusId, Error> {
        self.base.next(state)
    }

    /// Set current fuzzed corpus id and `scheduled_count`
    fn set_current_scheduled(
        &mut self,
        _state: &mut Self::State,
        _next_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        // We do nothing here, the inner scheduler will take care of it
        Ok(())
    }
}

impl<CS> CorpusLimitingScheduler<CS>
    where
        CS: Scheduler + RemovableScheduler,
        CS::State: HasCorpus + HasMetadata + HasRand,
{
    /// Get a reference to the base scheduler
    pub fn base(&self) -> &CS {
        &self.base
    }

    /// Get a reference to the base scheduler (mut)
    pub fn base_mut(&mut self) -> &mut CS {
        &mut self.base
    }

    /// Creates a new [`CorpusLimitingScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a default probability to skip non-faved [`Testcase`]s of [`DEFAULT_SKIP_NON_FAVORED_PROB`].
    pub fn new(base: CS, max_test_cases_with_same_code_cov: usize) -> Self {
        Self {
            base,
            max_test_cases_with_same_code_cov,
            code_cov_maps: Default::default(),
        }
    }
}