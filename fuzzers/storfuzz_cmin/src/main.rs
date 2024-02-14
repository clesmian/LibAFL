use std::env::var;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;


use libafl_bolts::{
    AsMutSlice,
    current_nanos,
    rands::StdRand,
    shmem::{
        ShMem,
        ShMemProvider,
        StdShMemProvider,
    },
    tuples::{
        tuple_list,
    },
};

use libafl::{
    corpus::{
        Corpus,
        OnDiskCorpus,
        CorpusMinimizer,
        StdCorpusMinimizer
}, events::SimpleEventManager, executors::{
    ForkserverExecutor,
    TimeoutForkserverExecutor,
}, feedback_and_fast, feedback_or, feedbacks::{
    AflMapFeedback,
    ConstFeedback,
    CrashFeedback,
    TimeFeedback,
}, fuzzer::StdFuzzer, inputs::BytesInput, monitors::{
    OnDiskTOMLMonitor,
    // Other monitors imported below according to used feature
}, observers::{
    ConstMapObserver,
    HitcountsMapObserver,
    TimeObserver,
}, schedulers::{
    QueueScheduler,
}, state::{
    HasCorpus,
    StdState,
}};

use libafl::monitors::SimpleMonitor;

use libafl::observers::MultiMapObserver;
use libafl_bolts::ownedref::OwnedMutSlice;

use libafl_targets::{
    STORFUZZ_MAP_SIZE,
    EDGES_MAP_SIZE
};

#[cfg(all(feature = "data-cov-only", feature = "edge-cov-only"))]
compile_error!("Cannot use features data-cov-only and edge-cov-only together");


#[derive(Parser)]
#[derive(Debug)]
#[command(about = "An AFL-like fuzzer built for fuzzbench")]
struct Arguments {
    #[arg(short, long, value_name = "PATH")]
    input_dir: PathBuf,
    #[arg(short, long, value_name = "PATH")]
    output_dir: PathBuf,
    #[arg(value_name = "EXE", allow_hyphen_values = true)]
    path_to_binary: PathBuf,
    #[arg(value_name = "ARG", allow_hyphen_values = true, help = "Arguments that are passed to the fuzz target. '@@' is replaced with the path to the current test case.")]
    args: Option<Vec<String>>,
    #[arg(short, long, default_value = "", value_name = "PATH", help = "Put '-' for stdout")]
    debug_logfile: String,
    #[arg(long, requires = "debug_logfile", default_value_t = false, help = "Prints stdout/stderr of the fuzz target to stdout of the fuzzing instance. Requires -d/--debug_logfile")]
    debug_child: bool,
    #[arg(long, default_value_t = cfg!(feature = "edge-cov-only"), help = "If enabled, the fuzzer disregards any coverage generated from data.", group = "coverage-selection")]
    disregard_data: bool,
    #[arg(long, default_value_t = cfg!(feature = "data-cov-only"), help = "If enabled, the fuzzer disregards any coverage generated from control-flow.", group = "coverage-selection")]
    disregard_edges: bool,
    #[arg(long, requires = "coverage-selection", default_value_t = false, help = "Do not evaluate coverage if we disregard it")]
    fast_disregard: bool,
    #[arg(long, short, default_value_t = 1000, help = "Timeout value in milliseconds")]
    timeout: u64,
}


fn main() {
    env_logger::init();

    let args = Arguments::parse();
    println!("{:#?}", args);

    #[cfg(feature = "data-cov-only")]
    if args.disregard_data {
        panic!("You cannot use the flag --disregard-data with this built, as it is configured \
        to evaluate data coverage only")
    }


    #[cfg(feature = "edge-cov-only")]
    if args.disregard_edges {
        panic!("You cannot use the flag --disregard-edges with this built, as it is configured \
        to evaluate edge coverage only")
    }

    if !args.input_dir.is_dir() {
        panic!("The value of input must be a directory")
    } else {
        match args.input_dir.read_dir() {
            Ok(entries) => if entries.count() == 0 {
                panic!("The input directory may not be empty")
            },
            Err(err) => panic!("{}", err)
        }
    }

    if !args.path_to_binary.is_file() {
        panic!("Could not find fuzz target at '{}'", args.path_to_binary.to_string_lossy())
    }

    if args.args == None || !args.args.clone().unwrap().contains(&String::from("@@")) {
        println!("WARNING: It seems that the test case is never passed to the fuzz target. Are you sure you did not forget to include '@@' in the commandline?")
    }


    if !args.output_dir.is_dir() {
        if args.output_dir.is_file() {
            panic!("ERROR: Given output directory is a file")
        } else {
            fs::create_dir_all(args.output_dir.to_owned()).expect("Failed to create output directory");
        }
    }

    // Save stats to disk every 60 seconds
    let stats = OnDiskTOMLMonitor::new(
        args.output_dir.join("stats.toml"),
        SimpleMonitor::with_user_monitor(|s| {println!("{}", s);},true),
    );

    let mut shmem_provider = StdShMemProvider::new().unwrap();
    let mut shmem_edges = shmem_provider.new_shmem(EDGES_MAP_SIZE).unwrap();

    shmem_edges
        .write_to_env("__AFL_SHM_ID")
        .expect("couldn't write shared memory id");

    println!("{}", var("__AFL_SHM_ID").unwrap());

    let mut shmem_data = shmem_provider.new_shmem(STORFUZZ_MAP_SIZE).unwrap();

    shmem_data
        .write_to_env("__STORFUZZ_SHM_ID")
        .expect("couldn't write shared memory id");

    println!("{}", var("__STORFUZZ_SHM_ID").unwrap());

    let minimizer_observer = MultiMapObserver::new("minimizer",
         unsafe {vec!{
             OwnedMutSlice::from_raw_parts_mut(shmem_edges.as_mut_slice().as_mut_ptr(), EDGES_MAP_SIZE),
             OwnedMutSlice::from_raw_parts_mut(shmem_data.as_mut_slice().as_mut_ptr(), STORFUZZ_MAP_SIZE),
         }}
        );

    let minimizer = StdCorpusMinimizer::new(&minimizer_observer);

    let edge_cov_observer =
        HitcountsMapObserver::new(ConstMapObserver::<_, EDGES_MAP_SIZE>::new(
        // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
        "edges",
        shmem_edges.as_mut_slice(),
    ));

    let data_cov_observer = ConstMapObserver::<_, STORFUZZ_MAP_SIZE>::new(
        // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
        "data",
        shmem_data.as_mut_slice(),
    );

    let time_observer = TimeObserver::new("time");

    let edge_feedback = AflMapFeedback::tracking(&edge_cov_observer, true, false);
    let mut data_feedback = AflMapFeedback::tracking(&data_cov_observer, true, false);
    data_feedback.set_is_bitmap(true);
    let data_feedback = data_feedback;

    let solution_corpus = OnDiskCorpus::<BytesInput>::new(args.output_dir.join("crashes")).unwrap();
    let queue_corpus = OnDiskCorpus::new(args.output_dir.join("minified-queue")).unwrap();

    let prog_path = args.path_to_binary.canonicalize().
        expect("Error during canonicalization of program path").to_owned();
    println!("Program located at: {:?}", prog_path.clone());

    let mut feedback = feedback_or!(
            feedback_and_fast!(ConstFeedback::new(!(args.disregard_edges && args.fast_disregard)),
                feedback_and_fast!(edge_feedback, ConstFeedback::new(!args.disregard_edges))),
            feedback_and_fast!(ConstFeedback::new(!(args.disregard_data && args.fast_disregard)),
                feedback_and_fast!(data_feedback, ConstFeedback::new(!args.disregard_data))),
            TimeFeedback::with_observer(&time_observer)
        );

    let mut objective = feedback_or!(
        TimeFeedback::with_observer(&time_observer),
        CrashFeedback::new()
    );

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        queue_corpus,
        solution_corpus,
        &mut feedback,
        &mut objective,
    ).unwrap();

    let scheduler = QueueScheduler::new();

    let mut fork_server_builder = ForkserverExecutor::builder()
        .program(prog_path);

    if args.args != None {
        for el in (args.args.clone()).unwrap() {
            if el == "@@" {
                fork_server_builder = fork_server_builder
                    .arg_input_file(args.output_dir.canonicalize().unwrap().join(".cur_input"));
            } else if el.contains("@@") {
                fork_server_builder = fork_server_builder.arg(el.replace("@@", ".cur_input"));
            } else {
                fork_server_builder = fork_server_builder.arg(el);
            }
        }
    }

    let observers = tuple_list!(edge_cov_observer, data_cov_observer, time_observer, minimizer_observer);

    let fork_server = fork_server_builder
        .debug_child(args.debug_child)
        .coverage_map_size(STORFUZZ_MAP_SIZE + EDGES_MAP_SIZE)
        .build(observers)
        .unwrap();

    let timeout = Duration::from_millis(args.timeout);

    let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout).unwrap();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(stats);



    let mut input_files: Vec<_> = fs::read_dir(&args.input_dir).unwrap()
                                              .map(|r| r.unwrap().path())
                                              .collect();
    println!("Initial test case import:");
    input_files.sort();
    input_files.reverse();
    state.
        load_initial_inputs_by_filenames(&mut fuzzer, &mut executor, &mut mgr, &input_files).unwrap();


    let orig_size = state.corpus().count();
    println!("Imported {} inputs from disk!\nMinimization phase", orig_size);

    minimizer.minimize(&mut fuzzer, &mut executor, &mut mgr, &mut state)
        .expect("Failed to minimize corpus");

    println!("Minimized corpus from {} to {} test cases ({}%)",
             orig_size, state.corpus().count(), 100*((state.corpus().count() as f64)/orig_size));
}
