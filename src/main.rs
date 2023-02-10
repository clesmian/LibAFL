use libafl::bolts::{AsMutSlice, current_nanos};
use libafl::corpus::Corpus;
use libafl::corpus::{InMemoryCorpus, OnDiskCorpus};
use libafl::events::{setup_restarting_mgr_std, SimpleEventManager};
use libafl::inputs::BytesInput;
use libafl::monitors::SimpleMonitor;
use libafl::prelude::{havoc_mutations, tuple_list, ConstMapObserver, ForkserverExecutor, HitcountsMapObserver, MaxMapFeedback, QueueScheduler, ShMemProvider, StdRand, StdScheduledMutator, StdShMemProvider, TimeFeedback, TimeObserver, TimeoutFeedback, TimeoutForkserverExecutor, ShMem, HasCorpus, MultiMonitor, CrashFeedback, SpliceMutator};
use libafl::schedulers::IndexesLenTimeMinimizerScheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::StdState;
use libafl::{Error, feedback_and_fast, feedback_or, feedback_or_fast, Fuzzer, StdFuzzer};
use std::path::{PathBuf};
use std::time::Duration;
use libafl::events::EventConfig::AlwaysUnique;

fn main() {
    let corpus_dir = vec![PathBuf::from("./corpus")];

    let input_corpus = InMemoryCorpus::<BytesInput>::new();

    let timeout_corpus =
        OnDiskCorpus::new(PathBuf::from("./timeouts")).expect("Could not create timeouts corpus");

    let time_observer = TimeObserver::new("time");

    const MAP_SIZE: usize = 65536;
    let mut shmem = StdShMemProvider::new().unwrap().new_shmem(MAP_SIZE).unwrap();

    shmem.write_to_env("__AFL_SHM_ID").expect("couldn't write shared memory id");

    let mut shmem_as_slice= shmem.as_mut_slice();

    let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
        "shared_mem",
        &mut shmem_as_slice,
    ));

    let mut feedback = feedback_or!(
        MaxMapFeedback::new_tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer)
    );

    let mut objective = feedback_or_fast!(feedback_and_fast!(CrashFeedback::new(), MaxMapFeedback::new(&edges_observer)),
        feedback_and_fast!(TimeoutFeedback::new(), MaxMapFeedback::new(&edges_observer)));



    let stats = MultiMonitor::new(|s| println!("{}", s));
    let (_, mut mgr) = match setup_restarting_mgr_std(stats, 1337, AlwaysUnique)
    {
        Ok(res) => res,
        Err(err) => if let Error::ShuttingDown = err {
            return;
        } else {
            panic!("Something happend while setting up event manager {}", err)
        }
    };

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        input_corpus,
        timeout_corpus,
        &mut feedback,
        &mut objective,
    ).unwrap();

    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let fork_server =
        ForkserverExecutor::builder().program("/home/leon/fuzzing-101/exercise-1/xpdf/install/bin/pdftotext".to_string())
            .parse_afl_cmdline(
                vec!("/home/leon/fuzzing-101/exercise-1/xpdf/install/bin/pdftotext".to_string(),"@@".to_string())
            ).build_dynamic_map(edges_observer, tuple_list!(time_observer)).unwrap();

    let timeout = Duration::from_secs(1);

    let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout).unwrap();

    if state.corpus().count() < 1 {
        state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dir).
            unwrap();
        println!("Imported {} inputs from disk!", state.corpus().count());
    }

    let mutator1 = StdScheduledMutator::new(havoc_mutations());
    let mutator2 = StdScheduledMutator::new(tuple_list!(SpliceMutator::new()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator1), StdMutationalStage::new(mutator2));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in fuzzing loop");
}
