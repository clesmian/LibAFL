use libafl::bolts::{current_nanos, AsMutSlice};
use libafl::corpus::Corpus;
use libafl::corpus::{InMemoryCorpus, OnDiskCorpus};
use libafl::events::setup_restarting_mgr_std;
use libafl::events::EventConfig::AlwaysUnique;
use libafl::inputs::BytesInput;
use libafl::prelude::{
    havoc_mutations, tuple_list, AflMapFeedback, ConstMapObserver, CrashFeedback,
    ForkserverExecutor, HasCorpus, HitcountsMapObserver, MultiMonitor, QueueScheduler, ShMem,
    ShMemProvider, SpliceMutator, StdRand, StdScheduledMutator, StdShMemProvider, TimeFeedback,
    TimeObserver, TimeoutFeedback, TimeoutForkserverExecutor,
};
use libafl::schedulers::IndexesLenTimeMinimizerScheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::StdState;
use libafl::{feedback_and_fast, feedback_or, feedback_or_fast, Error, Fuzzer, StdFuzzer};
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let corpus_dir = vec![PathBuf::from("./corpus")];

    let input_corpus = InMemoryCorpus::<BytesInput>::new();

    let solution_corpus =
        OnDiskCorpus::new(PathBuf::from("./timeouts")).expect("Could not create timeouts corpus");

    const MAP_SIZE: usize = 65536;
    let mut shmem_provider = StdShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();

    shmem
        .write_to_env("__AFL_SHM_ID")
        .expect("couldn't write shared memory id");

    let mut shmem_as_slice = shmem.as_mut_slice();

    let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
        "shared_mem",
        &mut shmem_as_slice,
    ));

    let time_observer = TimeObserver::new("time");

    let mut feedback = feedback_or!(
        AflMapFeedback::new_tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer)
    );

    let mut objective = feedback_or_fast!(
        feedback_and_fast!(CrashFeedback::new(), AflMapFeedback::new(&edges_observer)),
        feedback_and_fast!(TimeoutFeedback::new(), AflMapFeedback::new(&edges_observer))
    );

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        input_corpus,
        solution_corpus,
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let stats = MultiMonitor::new(|s| println!("{}", s));

    let (_, mut mgr) = match setup_restarting_mgr_std(stats, 1337, AlwaysUnique) {
        Ok(res) => res,
        Err(err) => {
            if let Error::ShuttingDown = err {
                return;
            } else {
                panic!("Something happened while setting up event manager {}", err)
            }
        }
    };

    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let fork_server = ForkserverExecutor::builder()
        .program("./xpdf/install/bin/pdftotext".to_string())
        .arg_input_file_std()
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(edges_observer, time_observer))
        .unwrap();

    let timeout = Duration::from_secs(1);

    let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout).unwrap();

    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dir)
            .unwrap();
        println!("Imported {} inputs from disk!", state.corpus().count());
    }

    let mutator1 = StdScheduledMutator::new(havoc_mutations());
    let mutator2 = StdScheduledMutator::new(tuple_list!(SpliceMutator::new()));
    let mut stages = tuple_list!(
        StdMutationalStage::new(mutator1),
        StdMutationalStage::new(mutator2)
    );

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in fuzzing loop");
}
