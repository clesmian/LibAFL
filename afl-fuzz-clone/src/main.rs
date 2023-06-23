use std::cell::RefCell;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use konst::{
    option::unwrap_or,
    primitive::parse_usize,
    result::unwrap_ctx,
};
use libafl::{
    bolts::{
        AsMutSlice,
        current_nanos,
        current_time,
        rands::StdRand,
    },
    corpus::{
        Corpus,
        OnDiskCorpus,
    },
    events::SimpleEventManager,
    executors::{
        ForkserverExecutor,
        TimeoutForkserverExecutor,
    },
    feedback_and_fast,
    feedback_or,
    feedbacks::{
        AflMapFeedback,
        ConstFeedback,
        CrashFeedback,
        TimeFeedback,
        TimeoutFeedback,
    },
    Fuzzer,
    fuzzer::StdFuzzer,
    inputs::BytesInput,
    monitors::{
        OnDiskTOMLMonitor,
        // Other monitors imported below according to used feature
    },
    mutators::StdMOptMutator,
    observers::{
        ConstMapObserver,
        HitcountsMapObserver,
        TimeObserver,
    },
    prelude::{
        havoc_mutations,
        Merge,
        ShMem,
        ShMemProvider,
        SpliceMutator,
        StdShMemProvider,
        tuple_list,
    },
    schedulers::{
        IndexesLenTimeMinimizerScheduler,
        powersched::PowerSchedule,
        StdWeightedScheduler,
    },
    stages::{
        CalibrationStage,
        StdPowerMutationalStage,
    },
    state::{
        HasCorpus,
        StdState,
    },
};
#[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
use libafl::{
    feedbacks::MapFeedbackMetadata,
    prelude::Named,
    state::HasNamedMetadata,
};
#[cfg(feature = "keep-queue-in-memory")]
use libafl::corpus::InMemoryCorpus;
#[cfg(not(feature = "keep-queue-in-memory"))]
use libafl::corpus::InMemoryOnDiskCorpus;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
#[cfg(feature = "tui")]
use libafl::monitors::tui::{
    TuiMonitor,
    ui::TuiUI,
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
    #[arg(long, short = 'T', default_value_t = false, help = "Consider timeouts to be solutions")]
    timeouts_are_solutions: bool,
    #[cfg(not(feature = "keep-queue-in-memory"))]
    #[arg(long, short = 'm', default_value_t = false, help = "Store metadata of queue entries on disk")]
    store_queue_metadata: bool,
    #[arg(long, default_value_t = false, help = "Output every log entry instead of only statys messages every few seconds")]
    fast_log_output: bool,
}


fn main() {
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

    let input_dir = vec![args.input_dir];


    if !args.output_dir.is_dir() {
        if args.output_dir.is_file() {
            panic!("ERROR: Given output directory is a file")
        } else {
            fs::create_dir_all(args.output_dir.to_owned()).expect("Failed to create output directory");
        }
    }

    let log =
        if !args.debug_logfile.is_empty() {
            let debug_log_path = args.output_dir.join(args.debug_logfile.clone()).to_str().unwrap().to_owned();
            Some(RefCell::new(OpenOptions::new().append(true).create(true).open(debug_log_path).expect("Failed to open log file")))
        } else {
            None
        };

    // We have to do it like this because of an error in IntelliJ-Rust
    // (https://github.com/intellij-rust/intellij-rust/issues/10222)
    #[cfg(not(feature = "tui"))]

        let mut last_log_event = current_time() - Duration::from_secs(30);
        // Save stats to disk every 60 seconds
        let stats = OnDiskTOMLMonitor::new(
        args.output_dir.join("stats.toml"),
        SimpleMonitor::with_user_monitor(
            |s| {
                if args.fast_log_output || last_log_event + Duration::from_secs(20) < current_time() {
                    last_log_event = current_time();
                    println!("{}", s);
                    if log.is_some() {
                        writeln!(log.as_ref().unwrap().borrow_mut(), "{:?} {}", current_time(), s).unwrap();
                    }
                }
            },
            true
        ),
    );
    #[cfg(feature = "tui")]
        // Save stats to disk every 60 seconds
        let stats = OnDiskTOMLMonitor::new(
        args.output_dir.join("stats.toml"),
        TuiMonitor::new(TuiUI::new(String::from("My Monitor"), true)),
    );


    // CHECK STARTING FROM HERE

    const CODE_MAP_SIZE: usize = 1 << 16;
    const DEFAULT_DATA_MAP_SIZE: usize = unwrap_ctx!(parse_usize(unwrap_or!(option_env!("DATA_MAP_SIZE"), "131072"))); // 1<<17 = 131072


    let map_size: usize = CODE_MAP_SIZE + DEFAULT_DATA_MAP_SIZE;

    let mut shmem_provider = StdShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(map_size).unwrap();

    shmem
        .write_to_env("__AFL_SHM_ID")
        .expect("couldn't write shared memory id");
    // To let the AFL++ binary know that we have a big map
    std::env::set_var("AFL_MAP_SIZE", format!("{}", map_size));

    let (shmem_edges, shmem_data) = shmem.as_mut_slice().split_at_mut(CODE_MAP_SIZE);

    #[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
    let calibration_observer = unsafe {
        ConstMapObserver::<_, { CODE_MAP_SIZE + DEFAULT_DATA_MAP_SIZE }>
            ::from_mut_ptr("two_as_one", shmem_edges.as_mut_ptr().clone())
    };

    let edge_cov_observer =
        HitcountsMapObserver::new(ConstMapObserver::<_, CODE_MAP_SIZE>::new(
        // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
        "shared_mem_edges",
        shmem_edges,
    ));

    let data_cov_observer = ConstMapObserver::<_, DEFAULT_DATA_MAP_SIZE>::new(
        // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
        "shared_mem_data",
        shmem_data,
    );

    let time_observer = TimeObserver::new("time");

    let edge_feedback = AflMapFeedback::tracking(&edge_cov_observer, true, false);
    let mut data_feedback = AflMapFeedback::tracking(&data_cov_observer, true, false);
    data_feedback.set_is_bitmap(true);

    let solutions_path = args.output_dir.join(PathBuf::from("crashes"));

    let solution_corpus =
        OnDiskCorpus::<BytesInput>::new(solutions_path).expect("Could not create crash corpus");

    // TODO: Implement commandline flag to be able to switch at runtime
    #[cfg(not(feature = "keep-queue-in-memory"))]
        let queue_corpus = if args.store_queue_metadata { 
            InMemoryOnDiskCorpus::<BytesInput>::new(args.output_dir.join("queue")).expect("Could not create queue corpus") 
        } else {
            InMemoryOnDiskCorpus::<BytesInput>::no_meta(args.output_dir.join("queue")).expect("Could not create queue corpus") 
        };
    #[cfg(feature = "keep-queue-in-memory")]
        let queue_corpus = InMemoryCorpus::<BytesInput>::new();

    let prog_path = args.path_to_binary.canonicalize().
        expect("Error during canonicalization of program path").to_owned();
    println!("Program located at: {:?}", prog_path.clone());

    #[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
    let calibration_feedback = AflMapFeedback::tracking(&calibration_observer, true, false);
    #[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
    let calibration_stage = CalibrationStage::new(&calibration_feedback);
    
    #[cfg(feature = "data-cov-only")]
    let calibration_stage = CalibrationStage::new(&data_feedback);
    #[cfg(feature = "edge-cov-only")]
    let calibration_stage = CalibrationStage::new(&edge_feedback);

    let mut feedback = feedback_or!(
            feedback_and_fast!(ConstFeedback::new(!(args.disregard_edges && args.fast_disregard)),
                feedback_and_fast!(edge_feedback, ConstFeedback::new(!args.disregard_edges))),
            feedback_and_fast!(ConstFeedback::new(!(args.disregard_data && args.fast_disregard)),
                feedback_and_fast!(data_feedback, ConstFeedback::new(!args.disregard_data))),
            TimeFeedback::with_observer(&time_observer)
        );

    let mut objective = feedback_or!(
        TimeFeedback::with_observer(&time_observer),
        CrashFeedback::new(),
        feedback_and_fast!(ConstFeedback::new(args.timeouts_are_solutions), TimeoutFeedback::new())
    );

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        queue_corpus,
        solution_corpus,
        &mut feedback,
        &mut objective,
    ).unwrap();

    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tuple_list!(SpliceMutator::new())),
        7,
        5
    ).unwrap();

    let mut stages = tuple_list!(
        calibration_stage,
        StdPowerMutationalStage::new(mutator)
        );

    #[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
        // Ensure that combined_feedback is present in the metadata map of the state
        state.add_named_metadata(
            // Doesn't really matter as it is overwritten anyways
            MapFeedbackMetadata::<u8>::new(0),
            &*calibration_feedback.name().to_string(),
        );

    // TODO: Check the impact of the observer here, maybe we have to do something else
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        StdWeightedScheduler::with_schedule(
            &mut state,
            #[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
                &calibration_observer,
            #[cfg(feature = "data-cov-only")]
                &data_cov_observer,
            #[cfg(feature = "edge-cov-only")]
                &edge_cov_observer,
            Some(PowerSchedule::EXPLORE)
        )
    );


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
    #[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
    let observers = tuple_list!(edge_cov_observer, data_cov_observer, time_observer, calibration_observer);
    #[cfg(any(feature = "data-cov-only", feature = "edge-cov-only"))]
    let observers = tuple_list!(edge_cov_observer, data_cov_observer, time_observer);


    // TODO: Consider is_persistent and build_dynamic_map
    let fork_server = fork_server_builder
        .debug_child(args.debug_child)
        .coverage_map_size(map_size)
        .build(observers)
        .unwrap();

    let timeout = Duration::from_millis(args.timeout);

    let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout).unwrap();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(stats);

    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &input_dir)
            .unwrap();
        println!("Imported {} inputs from disk!", state.corpus().count());
    }

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in fuzzing loop");
}
