use std::env::var;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use konst::{
    primitive::parse_usize,
    result::unwrap_ctx,
    option::unwrap_or,
};

use clap::Parser;
use libafl::{
    bolts::{
        AsMutSlice,
        core_affinity::{
            Cores,
            CoreId,
        },
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
    },
    corpus::{
        Corpus,
        OnDiskCorpus,
    },
    Error,
    events::{
        EventConfig,
        EventConfig::AlwaysUnique
    },
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
    observers::{
        ConstMapObserver,
        HitcountsMapObserver,
        TimeObserver,
    },
    prelude::{
        havoc_mutations,
        ShMem,
        ShMemProvider,
        SpliceMutator,
        StdScheduledMutator,
        StdShMemProvider,
        tuple_list,
    },
    schedulers::{
        IndexesLenTimeMinimizerScheduler,
        StdWeightedScheduler
    },
    stages::StdMutationalStage,
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


#[cfg(feature="variable-data-map-size")]
use libafl::observers::StdMapObserver;
#[cfg(feature="variable-data-map-size")]
use std::num::ParseIntError;

#[cfg(feature="variable-data-map-size")]
fn parse_maybe_hex(s: &str) -> Result<usize, ParseIntError> {
    if s.starts_with("0x") {
        usize::from_str_radix(s.trim_start_matches("0x"), 16)
    } else {
        s.parse()
    }
}

#[derive(Parser)]
#[derive(Debug)]
#[command(about="An AFL-like fuzzer with multi-core support")]
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
    #[arg(long, default_value_t = false, help="If enabled, the fuzzer disregards any coverage generated from data.", group = "coverage-selection")]
    disregard_data: bool,
    #[arg(long, default_value_t = false, help="If enabled, the fuzzer disregards any coverage generated from control-flow.", group = "coverage-selection")]
    disregard_edges: bool,
    #[arg(long, requires = "coverage-selection", default_value_t = false, help="Do not evaluate coverage if we disregard it")]
    fast_disregard: bool,
    #[arg(long, short, default_value_t = false, help="Creates a directory for each fuzzer instance to run its target in")]
    unique_working_dirs: bool,
    #[arg(long, short, default_value_t = 1000, help = "Timeout value in milliseconds")]
    timeout: u64,
    #[arg(long,short='T', default_value_t = false, help = "Consider timeouts to be solutions")]
    timeouts_are_solutions: bool,

    #[cfg(feature="variable-data-map-size")]
    #[arg(short='D', long, value_name = "SIZE", default_value_t=0x10000, value_parser=parse_maybe_hex)]
    data_map_size: usize,
}


fn main() {
    let args = Arguments::parse();
    println!("{:#?}", args);

    let default_asan_options =
        "abort_on_error=1:\
        detect_leaks=0:\
        malloc_context_size=0:\
        symbolize=0:\
        allocator_may_return_null=1".to_string();

    let asan_options = match var("ASAN_OPTIONS")  {
        Ok(options) => {format!("{}:{}", default_asan_options, options)}
        Err(_) => { default_asan_options }
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

    let mut run_client = |state: Option<_>, mut mgr, core_id: CoreId| {
        const CODE_MAP_SIZE: usize = 1 << 16;
        const DEFAULT_DATA_MAP_SIZE: usize = unwrap_ctx!(parse_usize(unwrap_or!(option_env!("DATA_MAP_SIZE"), "131072"))); // 1<<17 = 131072

        #[cfg(not(feature="variable-data-map-size"))]
            let map_size: usize = CODE_MAP_SIZE + DEFAULT_DATA_MAP_SIZE;
        #[cfg(feature="variable-data-map-size")]
            let map_size: usize = CODE_MAP_SIZE + args.data_map_size;

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut shmem = shmem_provider.new_shmem(map_size).unwrap();

        shmem
            .write_to_env("__AFL_SHM_ID")
            .expect("couldn't write shared memory id");

        let (shmem_edges, shmem_data) = shmem.as_mut_slice().split_at_mut(CODE_MAP_SIZE);

        let edges_cov_observer = HitcountsMapObserver::new(ConstMapObserver::<_, CODE_MAP_SIZE>::new(
            // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
            "shared_mem_edges",
            shmem_edges,
        ));

        #[cfg(feature="variable-data-map-size")]
            let data_cov_observer = unsafe {
                StdMapObserver::<_, false>::new(
                    // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
                    "shared_mem_data",
                    shmem_data,
                )
            };
        #[cfg(not(feature="variable-data-map-size"))]
            let data_cov_observer = ConstMapObserver::<_, DEFAULT_DATA_MAP_SIZE>::new(
                // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
                "shared_mem_data",
                shmem_data,
            );

        let time_observer = TimeObserver::new("time");

        let edge_feedback = AflMapFeedback::tracking(&edges_cov_observer, true, false);
        let data_feedback = AflMapFeedback::tracking(&data_cov_observer, true, false);

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
            let queue_corpus = InMemoryOnDiskCorpus::new(
                args.output_dir.join(format!("queue_{}", core_id.0))
                ).expect("Could not create queue corpus");
        #[cfg(feature = "keep-queue-in-memory")]
            let queue_corpus = InMemoryCorpus::<BytesInput>::new();

        let mut state = state.unwrap_or_else(|| {StdState::new(
                StdRand::with_seed(current_nanos()),
                queue_corpus,
                solution_corpus,
                &mut feedback,
                &mut objective,
            ).unwrap()}
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

        // TODO: Check the impact of the observer here, maybe we have to do something else
        let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::new(&mut state, &edges_cov_observer));

        let fork_server = fork_server_builder
            .debug_child(args.debug_child)
            .coverage_map_size(map_size)
            .build(tuple_list!(edges_cov_observer, data_cov_observer, time_observer))
            .unwrap();

        let timeout = Duration::from_millis(args.timeout);

        let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout).unwrap();

        let mutator1 = StdScheduledMutator::new(havoc_mutations());
        // TODO: Evaluate whether it makes sense to include two stages
        let mutator2 = StdScheduledMutator::new(tuple_list!(SpliceMutator::new()));
        let mut stages = tuple_list!(
            StdMutationalStage::new(mutator1),
            StdMutationalStage::new(mutator2)
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
