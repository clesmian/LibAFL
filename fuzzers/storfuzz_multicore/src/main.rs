use std::env::var;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use shadow_rs::shadow;
shadow!(build);

use storfuzz_constants::{DEFAULT_DATA_MAP_SIZE, CODE_MAP_SIZE, DEFAULT_ASAN_OPTIONS};

use libafl_bolts::{AsMutSlice, core_affinity::{
    Cores,
    CoreId,
}, current_nanos, rands::StdRand, shmem::{
    ShMem,
    ShMemProvider,
    StdShMemProvider,
}, tuples::{
    tuple_list,
    Merge,
}, Named};

use libafl_targets::coverage::autotokens;

use clap::Parser;
use libafl::{
    corpus::{
        Corpus,
        OnDiskCorpus,
    },
    Error,
    events::{
        EventConfig,
        EventConfig::AlwaysUnique,
        Launcher
    },
    executors::{
        ForkserverExecutor,
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
    observers::{
        ConstMapObserver,
        HitcountsMapObserver,
        TimeObserver,
    },
    prelude::{
        havoc_mutations,
        SpliceMutator,
        StdMOptMutator,
    },
    schedulers::{
        IndexesLenTimeMinimizerScheduler,
        StdWeightedScheduler
    },
    stages::{
        power::StdPowerMutationalStage,
    },
    state::{
        HasCorpus,
        StdState,
    },
};
#[cfg(not(feature = "keep-queue-in-memory"))]
use libafl::corpus::InMemoryOnDiskCorpus;
#[cfg(feature = "keep-queue-in-memory")]
use libafl::corpus::InMemoryCorpus;

#[cfg(not(feature="tui"))]
use libafl::monitors::MultiMonitor;
#[cfg(feature="tui")]
use libafl::monitors::tui::{
    ui::TuiUI,
    TuiMonitor,
};

#[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
use libafl::{
    feedbacks::MapFeedbackMetadata,
    state::HasNamedMetadata,
};

#[cfg(all(feature = "data-cov-only", feature = "edge-cov-only"))]
compile_error!("Cannot use features data-cov-only and edge-cov-only together");

#[cfg(feature="variable-data-map-size")]
compile_error!("Variable data map size is not supported anymore");

use libafl::mutators::Tokens;
use libafl::mutators::TokenReplace;
use libafl::observers::MultiMapObserver;
use libafl::schedulers::powersched::PowerSchedule;
use libafl::stages::CalibrationStage;
use libafl::state::HasMetadata;
use libafl_bolts::prelude::OwnedMutSlice;
use libafl_targets::EDGES_MAP_SIZE;

#[cfg(feature = "data-cov-only")]
const ABOUT: & str = "AFL-like fuzzer (DATA only)";
#[cfg(feature = "edge-cov-only")]
const ABOUT: & str = "AFL-like fuzzer (EDGES only)";
#[cfg(not(any(feature = "edge-cov-only", feature = "data-cov-only")))]
const ABOUT: & str = "An AFL-like fuzzer with multi-core support";


#[derive(Parser)]
#[derive(Debug)]
#[command(about=ABOUT, version=build::CLAP_LONG_VERSION)]
struct Arguments {
    #[arg(short, long, value_name = "PATH")]
    input_dir: PathBuf,
    #[arg(short, long, value_name = "PATH")]
    output_dir: PathBuf,
    #[arg(value_name = "EXE", allow_hyphen_values=true)]
    path_to_binary: PathBuf,
    #[arg(value_name = "ARG", allow_hyphen_values=true, help="Arguments that are passed to the fuzz target. '@@' is replaced with the path to the current test case.")]
    args: Option<Vec<String>>,
    #[arg(short = 'p', long, value_name = "PORT", default_value_t= 1337)]
    broker_port: u16,
    #[arg(
    short,
    long,
    value_parser = Cores::from_cmdline,
    help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
    name = "CORES",
    default_value= "1"
    )]
    cores: Cores,
    #[arg(short, long, default_value = "", value_name="PATH", help="Put '-' for stdout")]
    debug_logfile: String,
    #[arg(long, requires = "debug_logfile", default_value_t = false, help="Prints stdout/stderr of the fuzz target to stdout of the fuzzing instance. Requires -d/--debug_logfile")]
    debug_child: bool,
    #[arg(short, long, default_value_t = false)]
    attach_to_running_broker: bool,
    #[arg(short='C', long, default_value_t = false, help="If enabled, the config is derived from the executable path and its arguments, which enables all fuzzers of the broker running the same executable to share test cases in an easier fashion. Use unique config by default.")]
    config_from_name: bool,
    #[arg(long, default_value_t = cfg!(feature = "edge-cov-only"), help = "If enabled, the fuzzer disregards any coverage generated from data.", group = "coverage-selection")]
    disregard_data: bool,
    #[arg(long, default_value_t = cfg!(feature = "data-cov-only"), help = "If enabled, the fuzzer disregards any coverage generated from control-flow.", group = "coverage-selection")]
    disregard_edges: bool,
    #[arg(long, requires = "coverage-selection", default_value_t = false, help="Do not evaluate coverage if we disregard it")]
    fast_disregard: bool,
    #[arg(long, short, default_value_t = false, help="Creates a directory for each fuzzer instance to run its target in")]
    unique_working_dirs: bool,
    #[arg(long, short, default_value_t = 1000, help = "Timeout value in milliseconds")]
    timeout: u64,
    #[arg(long,short='T', default_value_t = false, help = "Consider timeouts to be solutions")]
    timeouts_are_solutions: bool,
    #[cfg(not(feature = "keep-queue-in-memory"))]
    #[arg(long, short = 'm', default_value_t = false, help = "Store metadata of queue entries on disk")]
    store_queue_metadata: bool,
    #[cfg(not(feature = "keep-queue-in-memory"))]
    #[arg(long, short = 'Q', help = "Store queue in this directory instead of one dir per fuzzer under out")]
    queue_directory: Option<PathBuf>,
    #[arg(long, help = "Fixed seed for RNG (each fuzzer gets its own seed derived from the supplied value)")]
    seed: Option<u64>,
    #[arg(value_name = "FILE", long, short='x', help = "Token file as produced by autotokens pass")]
    tokenfile: Option<PathBuf>,
}


fn main() {
    let args = Arguments::parse();
    println!("{}", ABOUT);
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

    let asan_options = match var("ASAN_OPTIONS")  {
        Ok(options) => {format!("{}:{}", DEFAULT_ASAN_OPTIONS, options)}
        Err(_) => { DEFAULT_ASAN_OPTIONS.to_string() }
    };
    println!("Setting ASAN_OPTIONS to: '{}'", &asan_options);

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
    let tokenfile = args.tokenfile;

    let mut run_client = |state: Option<_>, mut mgr, core_id: CoreId| {

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut shmem_edges = shmem_provider.new_shmem(CODE_MAP_SIZE).unwrap();

        shmem_edges
            .write_to_env("__AFL_SHM_ID")
            .expect("couldn't write shared memory id");

        println!("{}", var("__AFL_SHM_ID").unwrap());

        let mut shmem_data = shmem_provider.new_shmem(DEFAULT_DATA_MAP_SIZE).unwrap();

        shmem_data
            .write_to_env("__STORFUZZ_SHM_ID")
            .expect("couldn't write shared memory id");

        println!("{}", var("__STORFUZZ_SHM_ID").unwrap());

        let calibration_observer = MultiMapObserver::new("calibration",
                                                         unsafe {vec!{
                                                             OwnedMutSlice::from_raw_parts_mut(shmem_edges.as_mut_slice().as_mut_ptr(), EDGES_MAP_SIZE),
                                                             OwnedMutSlice::from_raw_parts_mut(shmem_data.as_mut_slice().as_mut_ptr(), DEFAULT_DATA_MAP_SIZE),
                                                         }}
        );

        let edge_cov_observer =
            HitcountsMapObserver::new(ConstMapObserver::<_, CODE_MAP_SIZE>::new(
            // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
            "edges",
            shmem_edges.as_mut_slice(),
        ));

        let data_cov_observer = ConstMapObserver::<_, DEFAULT_DATA_MAP_SIZE>::new(
            // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
            "data",
            shmem_data.as_mut_slice(),
        );


        let time_observer = TimeObserver::new("time");

        let edge_feedback = AflMapFeedback::tracking(&edge_cov_observer, true, false);
        let mut data_feedback = AflMapFeedback::tracking(&data_cov_observer, true, false);
        data_feedback.set_is_bitmap(true);
        let data_feedback = data_feedback;

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

        let solutions_path = args.output_dir.join(PathBuf::from("crashes"));

        let solution_corpus =
            OnDiskCorpus::<BytesInput>::new(solutions_path).expect("Could not create crash corpus");

        // TODO: Implement commandline flag to be able to switch at runtime
        #[cfg(not(feature = "keep-queue-in-memory"))]
        let queue_dir = match args.queue_directory.clone() {
            None => args.output_dir.join(format!("queue_{}", core_id.0)),
            Some(dir) => dir
        };

        #[cfg(not(feature = "keep-queue-in-memory"))]
        let queue_corpus = if args.store_queue_metadata {
            InMemoryOnDiskCorpus::new(queue_dir).expect("Could not create queue corpus")
        } else {
            InMemoryOnDiskCorpus::no_meta(queue_dir).expect("Could not create queue corpus")
        };

        #[cfg(feature = "keep-queue-in-memory")]
            let queue_corpus = InMemoryCorpus::<BytesInput>::new();

        // Don't depend on the concrete cores selected, but only on the number of cores selected
        let mut core_id_for_rand = 0;
        for i in 0..args.cores.ids.len(){
            if args.cores.ids[i] == core_id {
                core_id_for_rand = i;
                break;
            }
        };


        let mut state = state.unwrap_or_else(|| {StdState::new(
                StdRand::with_seed(if args.seed.is_none() {
                    current_nanos()
                } else {
                    args.seed.unwrap() + (core_id_for_rand as u64)
                }),
                queue_corpus,
                solution_corpus,
                &mut feedback,
                &mut objective,
            ).unwrap()}
            );

        #[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
        // Ensure that combined_feedback is present in the metadata map of the state
        state.add_named_metadata(
            // Doesn't really matter as it is overwritten anyways
            MapFeedbackMetadata::<u8>::new(0),
            &*calibration_feedback.name().to_string(),
        );

        let prog_path = args.path_to_binary.canonicalize().
            expect("Error during canonicalization of program path").to_owned();
        println!("Program located at: {:?}", prog_path.clone());

        let mut fork_server_builder = ForkserverExecutor::builder()
            .program(prog_path);

        if args.unique_working_dirs{
            let work_dir = args.output_dir.join(format!("fuzz_dir_{}",core_id.0));
            if !work_dir.exists() {
                println!("Creating work dir: {:?}", work_dir.clone());
                fs::create_dir_all(work_dir.clone()).expect("Failed to create work_dir for executor");
            }

            fork_server_builder =
                fork_server_builder.current_dir(work_dir.canonicalize().unwrap().as_os_str());

        } else {
            fork_server_builder =
                fork_server_builder.current_dir(args.output_dir.canonicalize().unwrap().as_os_str());
        }
        
        fork_server_builder = fork_server_builder.env("ASAN_OPTIONS", &asan_options);

        if args.args != None {
            for el in (args.args.clone()).unwrap() {
                if el == "@@" {
                    fork_server_builder = fork_server_builder
                        .arg_input_file(args.output_dir.canonicalize().unwrap().join(format!(".cur_input_{}",core_id.0)));
                } else if el.contains("@@") {
                    fork_server_builder = fork_server_builder.arg(el.replace("@@", format!(".cur_input_{}",core_id.0).as_str()));
                } else {
                    fork_server_builder = fork_server_builder.arg(el);
                }
            }
        }

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

        #[cfg(not(any(feature = "data-cov-only", feature = "edge-cov-only")))]
            let observers = tuple_list!(edge_cov_observer, data_cov_observer, time_observer, calibration_observer);
        #[cfg(any(feature = "data-cov-only", feature = "edge-cov-only"))]
            let observers = tuple_list!(edge_cov_observer, data_cov_observer, time_observer);

        let timeout = Duration::from_millis(args.timeout);

        let mut executor = fork_server_builder
            .debug_child(args.debug_child)
            .coverage_map_size(DEFAULT_DATA_MAP_SIZE + EDGES_MAP_SIZE)
            .timeout(timeout)
            .build(observers)
            .unwrap();


        if var("AFL_NO_AUTODICT").is_err() && state.metadata_map().get::<Tokens>().is_none() {
            let mut toks = Tokens::default();
            if let Some(tokenfile) = tokenfile.clone(){
                toks.add_from_file(tokenfile)?;
            }
            #[cfg(any(target_os = "linux", target_vendor = "apple"))]
            {
                match autotokens() {
                    Ok(tokens) => {
                        toks += tokens;
                    },
                    Err(e) => eprintln!("Failed to extract autotokens {}", e)
                }
            }

            if !toks.is_empty() {
                println!("Using {} tokens from autotokens pass ", toks.len());
                state.add_metadata(toks);
            }
        }


        // Uses values from LibAFL fuzzbench fuzzers
        let mutator = StdMOptMutator::new(
            &mut state,
            havoc_mutations().merge(
                tuple_list!(SpliceMutator::new(), TokenReplace::new())
            ),
            7,
            5
        )?;

        let mut stages = tuple_list!(
            calibration_stage,
            StdPowerMutationalStage::new(mutator)
        );

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        println!("We're a client on core {}, let's fuzz :)", core_id.0);

        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &input_dir)
                .unwrap();
            println!("Imported {} inputs from disk!", state.corpus().count());
        }

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in fuzzing loop");
        Ok(())

    };


    #[cfg(not(feature = "keep-queue-in-memory"))]
    if args.queue_directory.is_some(){
        let dir = args.queue_directory.clone().unwrap();
        if !dir.exists(){
            fs::create_dir(dir.clone()).expect("Failed to create queue_dir");
        }
        if !dir.is_dir() || fs::read_dir(dir.clone()).unwrap().count() != 0 {
            panic!("ERROR: Designated queue dir {:?} is not an empty directory!", dir)
        }

    }

    if !args.output_dir.is_dir(){
        if args.output_dir.is_file(){
            panic!("ERROR: Given output directory is a file")
        } else {
            fs::create_dir_all(args.output_dir.to_owned()).expect("Failed to create output directory");
        }
    }

    let debug_log_path = args.output_dir.join(args.debug_logfile.clone()).to_str().unwrap().to_owned();

    // We have to do it like this because of an error in IntelliJ-Rust
    // (https://github.com/intellij-rust/intellij-rust/issues/10222)
    #[cfg(not(feature = "tui"))]
        // Save stats to disk every 60 seconds
        let stats = OnDiskTOMLMonitor::new(
        args.output_dir.join("stats.toml"),
        MultiMonitor::new(|s| println!("{}", s)),
        );
    #[cfg(feature = "tui")]
        // Save stats to disk every 60 seconds
        let stats = OnDiskTOMLMonitor::new(
            args.output_dir.join("stats.toml"),
            TuiMonitor::new(TuiUI::new(String::from("My Monitor"), true))
        );

    let mut config_string = String::from(args.path_to_binary.to_str().unwrap());
    if args.args != None {
        for el in args.args.clone().unwrap() {
            config_string += &*el;
        }
    }

    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new().
            expect("Failed to initialize shared memory for launcher"))
        .monitor(stats)
        // Let all fuzzing instances fuzzing the same binary use the same config for now.
        // Let's them exchange every input without needing to rerun it
        .configuration(
            if args.config_from_name {
                EventConfig::from_name(&*config_string)
            } else {
                AlwaysUnique
            })
        .run_client(&mut run_client)
        .broker_port(args.broker_port)
        .cores(&args.cores)
        // .stdout_file(Some(args.output_dir.join(PathBuf::from("fuzzers.log")).to_str().unwrap()))
        .stdout_file(
            if args.debug_logfile == "-" {
                // Use stdout
                None
            } else if args.debug_logfile.is_empty(){
                // If no log file is given, pipe debug output into the void
                Some("/dev/null")
            } else {
                Some(&*debug_log_path)
            }
        )
        .spawn_broker(!args.attach_to_running_broker)
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }


}
