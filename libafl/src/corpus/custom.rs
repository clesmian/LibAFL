//! The [`CustomInMemOnDiskCorpus`] stores [`Testcase`]s to disk, keeping a subset of them in memory/cache, evicting in a FIFO manner.

use alloc::{collections::vec_deque::VecDeque, string::String, vec::Vec};
use core::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use log::debug;

use serde::{Deserialize, Serialize};
use libafl_bolts::AsSlice;

use crate::{
    corpus::{
        inmemory_ondisk::InMemoryOnDiskCorpus, ondisk::OnDiskMetadataFormat, Corpus, CorpusId,
        HasTestcase, Testcase,
    },
    inputs::{Input, UsesInput},
    Error,
};
use crate::prelude::MapIndexesMetadata;
use crate::state::HasMetadata;

/// A corpus that keeps a maximum number of [`Testcase`]s in memory
/// and load them from disk, when they are being used.
/// The eviction policy is FIFO.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct CustomInMemOnDiskCorpus<I>
where
    I: Input,
{
    inner: InMemoryOnDiskCorpus<I>,
    max_test_cases_with_same_code_cov: usize,
    code_cov_maps: HashMap<Vec<usize>, VecDeque<CorpusId>>,
}

impl<I> UsesInput for CustomInMemOnDiskCorpus<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> Corpus for CustomInMemOnDiskCorpus<I>
    where
        I: Input,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.inner.count()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        if let Ok(meta) = testcase.metadata::<MapIndexesMetadata>(){
            let meta_as_vec = Vec::from(meta.as_slice());
            if let Some(test_cases) = self.code_cov_maps.get_mut(&meta_as_vec){
                debug!("We know {} testcases with the same code coverage", test_cases.len());
                while test_cases.len() >= self.max_test_cases_with_same_code_cov {
                    // TODO Is there a more useful strategy?
                    let to_remove = test_cases.pop_back();
                    debug!("Removing test case {:?}", to_remove);
                    self.inner.remove(to_remove.unwrap()).unwrap();
                }
            } else {
                self.code_cov_maps.insert(meta_as_vec.clone(), VecDeque::from([]));
            }
            let corpus_id = self.inner.add(testcase)?;
            self.code_cov_maps.get_mut(&meta_as_vec).unwrap().push_front(corpus_id);
            return Ok(corpus_id)
        } else {
            return Err(
                Error::NotImplemented(
                    "Cannot add test case as there is no MapIndexesMetadata for testcase".parse().unwrap(),
                    Default::default()
                )
            )
        }
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        self.inner.replace(idx, testcase)
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: CorpusId) -> Result<Testcase<I>, Error> {
        let testcase = self.inner.remove(idx)?;
        Ok(testcase)
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        let testcase = { self.inner.get(idx)? };
        Ok(testcase)
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        self.inner.current()
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        self.inner.current_mut()
    }

    #[inline]
    fn next(&self, idx: CorpusId) -> Option<CorpusId> {
        self.inner.next(idx)
    }

    #[inline]
    fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
        self.inner.prev(idx)
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        self.inner.first()
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        self.inner.last()
    }

    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        self.inner.nth(nth)
    }

    #[inline]
    fn load_input_into(&self, testcase: &mut Testcase<Self::Input>) -> Result<(), Error> {
        self.inner.load_input_into(testcase)
    }

    #[inline]
    fn store_input_from(&self, testcase: &Testcase<Self::Input>) -> Result<(), Error> {
        self.inner.store_input_from(testcase)
    }
}

impl<I> HasTestcase for CustomInMemOnDiskCorpus<I>
where
    I: Input,
{
    fn testcase(&self, id: CorpusId) -> Result<core::cell::Ref<Testcase<Self::Input>>, Error> {
        Ok(self.get(id)?.borrow())
    }

    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<core::cell::RefMut<Testcase<Self::Input>>, Error> {
        Ok(self.get(id)?.borrow_mut())
    }
}

impl<I> CustomInMemOnDiskCorpus<I>
where
    I: Input,
{
    /// Creates the [`CustomInMemOnDiskCorpus`].
    ///
    /// By default, it stores metadata for each [`Testcase`] as prettified json.
    /// Metadata will be written to a file named `.<testcase>.metadata`
    /// the metadata may include objective reason, specific information for a fuzz job, and more.
    ///
    /// If you don't want metadata, use [`CustomInMemOnDiskCorpus::no_meta`].
    /// to pick a different metadata format, use [`CustomInMemOnDiskCorpus::with_meta_format`].
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new<P>(dir_path: P, max_test_cases_with_same_code_cov: usize) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(InMemoryOnDiskCorpus::new(dir_path)?, max_test_cases_with_same_code_cov)
    }

    /// Creates an [`CustomInMemOnDiskCorpus`] that does not store [`Testcase`] metadata to disk.
    pub fn no_meta<P>(dir_path: P, max_test_cases_with_same_code_cov: usize) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(InMemoryOnDiskCorpus::no_meta(dir_path)?, max_test_cases_with_same_code_cov)
    }

    /// Creates the [`CustomInMemOnDiskCorpus`] specifying the format in which `Metadata` will be saved to disk.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format<P>(
        dir_path: P,
        max_test_cases_with_same_code_cov: usize,
        meta_format: Option<OnDiskMetadataFormat>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(
            InMemoryOnDiskCorpus::with_meta_format(dir_path, meta_format)?,
            max_test_cases_with_same_code_cov,
        )
    }

    /// Creates the [`CustomInMemOnDiskCorpus`] specifying the metadata format and the prefix to prepend
    /// to each testcase.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format_and_prefix<P>(
        dir_path: P,
        max_test_cases_with_same_code_cov: usize,
        meta_format: Option<OnDiskMetadataFormat>,
        prefix: Option<String>,
        locking: bool,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(
            InMemoryOnDiskCorpus::with_meta_format_and_prefix(
                dir_path,
                meta_format,
                prefix,
                locking,
            )?,
            max_test_cases_with_same_code_cov,
        )
    }

    /// Internal constructor `fn`
    fn _new(on_disk_corpus: InMemoryOnDiskCorpus<I>, max_test_cases_with_same_code_cov: usize) -> Result<Self, Error> {
        if max_test_cases_with_same_code_cov == 0 {
            return Err(Error::illegal_argument(
                "The max_test_cases_with_same_code_cov in CustomInMemOnDiskCorpus cannot be 0",
            ));
        }
        Ok(Self {
            inner: on_disk_corpus,
            code_cov_maps: HashMap::new(),
            max_test_cases_with_same_code_cov,
        })
    }

    /// Fetch the inner corpus
    pub fn inner(&self) -> &InMemoryOnDiskCorpus<I> {
        &self.inner
    }
}