use std::env::var;
use std::{fs, thread};
use std::path::PathBuf;
use std::time::Duration;

use zafl_constants::{
    DEFAULT_DATA_MAP_SIZE,
    CODE_MAP_SIZE
};

use clap::Parser;
use libafl::{bolts::{
    AsMutSlice,
    core_affinity::{
        Cores,
        CoreId,
    },
    current_nanos,
    launcher::Launcher,
    rands::StdRand,
}, corpus::{
    Corpus,
    InMemoryOnDiskCorpus,
}, Error, events::{
    EventConfig::AlwaysUnique
}, executors::{
    ForkserverExecutor,
    TimeoutForkserverExecutor,
}, feedback_or, feedback_or_fast, feedbacks::{
    AflMapFeedback,
    TimeFeedback,
    ConstFeedback,
}, Fuzzer, fuzzer::StdFuzzer, inputs::BytesInput, none_input_converter, observers::{
    ConstMapObserver,
    HitcountsMapObserver,
    TimeObserver,
}, prelude::{
    ShMem,
    ShMemProvider,
    StdShMemProvider,
    tuple_list,
}, state::{
    HasCorpus,
    StdState,
}};
#[cfg(feature="variable-data-map-size")]
use libafl::observers::StdMapObserver;
#[cfg(feature="variable-data-map-size")]
use std::num::ParseIntError;
use libafl::corpus::InMemoryCorpus;
use libafl::events::{EventRestarter, LlmpEventConverter, LlmpRestartingEventManager};
use libafl::inputs::NopInputConverter;
use libafl::monitors::MultiMonitor;
use libafl::schedulers::QueueScheduler;
use libafl::stages::{SyncFromBrokerStage};

#[cfg(feature="variable-data-map-size")]
fn parse_maybe_hex(s: &str) -> Result<usize, ParseIntError> {
    if s.starts_with("0x") {
        usize::from_str_radix(s.trim_start_matches("0x"), 16)
    } else {
        s.parse()
    }
}

const ABOUT: & str = "Attaches to a running broker and dumps its corpus to out-dir. All arguments except \
--out-dir/-o should be the same as the original fuzzer instance";


#[derive(Parser)]
#[derive(Debug)]
#[command(about=ABOUT)]
struct Arguments {
    #[arg(short, long, value_name = "PATH", )]
    input_dir: PathBuf,
    #[arg(short, long, value_name = "PATH")]
    output_dir: PathBuf,
    #[arg(value_name = "EXE", allow_hyphen_values=true)]
    path_to_binary: PathBuf,
    #[arg(value_name = "ARG", allow_hyphen_values=true, help="Arguments that are passed to the fuzz target. '@@' is replaced with the path to the current test case.")]
    args: Option<Vec<String>>,
    #[arg(long, short, default_value_t = 1000, help = "Timeout value in milliseconds")]
    timeout: u64,
    #[arg(short = 'p', long, value_name = "PORT", default_value_t= 1337)]
    broker_port: u16,
    #[arg(
    short,
    long,
    value_parser = Cores::from_cmdline,
    help = "Use only one core, which should not be in use yet",
    name = "CORES",
    default_value= "1"
    )]
    cores: Cores,
    #[arg(long, default_value_t = false, help="Prints stdout/stderr of the fuzz target to stdout of the fuzzing instance")]
    debug_child: bool,
    #[arg(long, short = 'm', default_value_t = false, help = "Store metadata of queue entries on disk")]
    store_queue_metadata: bool,
    #[cfg(feature="variable-data-map-size")]
    #[arg(short='D', long, value_name = "SIZE", default_value_t=0x10000, value_parser=parse_maybe_hex)]
    data_map_size: usize,
    #[arg(long, short, default_value_t = false, help = "Consider all test cases as interesting, may lead to duplications in output.")]
    all_are_interesting: bool,
    #[arg(long, short, default_value_t = 0, value_name = "SEC", help = "Restart dumping test cases <SEC> seconds after it is done")]
    repeatedly_dump: u64,
}


fn main() {
    let args = Arguments::parse();
    println!("{}", ABOUT);
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
    let input_dir = vec![args.input_dir];

    if !args.path_to_binary.is_file() {
        panic!("Could not find fuzz target at '{}'", args.path_to_binary.to_string_lossy())
    }

    if args.args == None || !args.args.clone().unwrap().contains(&String::from("@@")) {
        println!("WARNING: It seems that the test case is never passed to the fuzz target. Are you sure you did not forget to include '@@' in the commandline?")
    }


    let mut run_client = |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, StdShMemProvider>, core_id: CoreId| {
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

        let edge_cov_observer =
            HitcountsMapObserver::new(ConstMapObserver::<_, CODE_MAP_SIZE>::new(
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

        let edge_feedback = AflMapFeedback::tracking(&edge_cov_observer, true, false);
        let mut data_feedback = AflMapFeedback::tracking(&data_cov_observer, true, false);
        data_feedback.set_is_bitmap(true);

        let mut feedback = feedback_or_fast!(
            feedback_or!(
                edge_feedback,
                data_feedback,
                TimeFeedback::with_observer(&time_observer)
            ),
            ConstFeedback::new(args.all_are_interesting)
        );

        // We do not care about the solutions
        let mut objective = feedback_or!(ConstFeedback::new(false));
        let solution_corpus =
            InMemoryCorpus::<BytesInput>::new();

        // We need InMemoryOnDiskCorpus to be able to choose whether metadata is saved to disk
        let queue_corpus = if args.store_queue_metadata {
            InMemoryOnDiskCorpus::new(
                args.output_dir.clone()
            ).expect("Could not create queue corpus")
        } else {
            InMemoryOnDiskCorpus::no_meta(
                args.output_dir.clone()
            ).expect("Could not create queue corpus")
        };

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

        let scheduler = QueueScheduler::new();

        let observers = tuple_list!(edge_cov_observer, data_cov_observer, time_observer);

        let mut fork_server_builder = ForkserverExecutor::builder()
            .program(prog_path)
            .current_dir(args.output_dir.canonicalize().unwrap().as_os_str())
            .env("ASAN_OPTIONS", &asan_options);

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

        let fork_server = match fork_server_builder
            .debug_child(args.debug_child)
            .coverage_map_size(map_size)
            .build(observers){
            Ok(fs) => Ok(fs),
            Err(err) => {
                // A bit hacky, but it works
                _ = mgr.send_exiting();
                Err(err)
            }
        }.unwrap();

        let timeout = Duration::from_millis(args.timeout);
        let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout).unwrap();

        let converter = LlmpEventConverter::on_port(
            shmem_provider.clone(),
            args.broker_port,
            Some(NopInputConverter::<BytesInput>::default()),
            none_input_converter!()
        ).unwrap();

        let mut stages = tuple_list!(
            SyncFromBrokerStage::new(converter),
        );

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        println!("We're a client on core {}, let's try to get all test cases :)", core_id.0);

        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &input_dir)
                .unwrap();
        }

        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in fuzzing loop");

        println!("Dumped {} test cases to disk", state.corpus().count());

        if args.repeatedly_dump == 0 {
            // Tell the manager to not respawn this process
            let _ = &mgr.send_exiting()?;
        } else {
            loop {
                println!("Restarting dump in {} seconds", args.repeatedly_dump);
                thread::sleep(Duration::from_secs(args.repeatedly_dump));
                println!("Dumping test cases");
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
                    .expect("Error in fuzzing loop");
                println!("Dumped {} test cases to disk", state.corpus().count());
            }
        }

        Ok(())
    };


    if !args.output_dir.is_dir(){
        if args.output_dir.is_file(){
            panic!("ERROR: Given output directory is a file")
        } else {
            fs::create_dir_all(args.output_dir.to_owned()).expect("Failed to create output directory");
        }
    }

    let stats = MultiMonitor::new(|s| println!("{}", s));

    let mut core = args.cores.clone();
    core.trim(1).expect("Failed to reduce cores down to one!");

    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new().
            expect("Failed to initialize shared memory for launcher"))
        .monitor(stats)
        .configuration(AlwaysUnique)
        .run_client(&mut run_client)
        .broker_port(args.broker_port)
        .cores(&core)
        .stdout_file(None) // Print to stdout
        .spawn_broker(false) // Attach to broker running on args.broker_port
        .serialize_state(false) // Prevent crash
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Dumping stopped. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}
