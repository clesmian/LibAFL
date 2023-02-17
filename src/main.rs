use std::fs;
use libafl::bolts::{current_nanos, AsMutSlice};
use libafl::corpus::Corpus;
use libafl::corpus::{OnDiskCorpus};
use libafl::inputs::BytesInput;
use libafl::prelude::{havoc_mutations, tuple_list, AflMapFeedback, ConstMapObserver, CrashFeedback, ForkserverExecutor, HasCorpus, HitcountsMapObserver, QueueScheduler, ShMem, ShMemProvider, SpliceMutator, StdRand, StdScheduledMutator, StdShMemProvider, TimeFeedback, TimeObserver, TimeoutFeedback, TimeoutForkserverExecutor, Launcher, Cores, InMemoryCorpus, OnDiskTOMLMonitor, EventConfig};
use libafl::schedulers::IndexesLenTimeMinimizerScheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::StdState;
use libafl::{feedback_and_fast, feedback_or, feedback_or_fast, Error, Fuzzer, StdFuzzer};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser};
use libafl::prelude::EventConfig::AlwaysUnique;
use libafl::prelude::tui::TuiMonitor;

#[derive(Parser)]
struct Arguments {
    #[arg(short, long, value_name = "PATH")]
    input_dir: PathBuf,
    #[arg(short, long, value_name = "PATH")]
    output_dir: PathBuf,
    #[arg(value_name = "EXE")]
    path_to_binary: PathBuf,
    #[arg(short = 'p', long, value_name = "PORT", default_value_t= 1337)]
    broker_port: u16,
    #[arg(short = 'Q', long, default_value_t= false)]
    store_queue_to_disk: bool,
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
    #[arg(short, long, default_value = "false")]
    attach_to_running_broker: bool,
}


fn main() {
    let args = Arguments::parse();
    let input_dir = vec![args.input_dir];

    let mut run_client = |state: Option<_>, mut mgr, core_id| {
        const MAP_SIZE: usize = 65536;
        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();

        shmem
            .write_to_env("__AFL_SHM_ID")
            .expect("couldn't write shared memory id");

        let mut shmem_as_slice = shmem.as_mut_slice();

        let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
            // Must be the same name for all fuzzing instances with the same configuration, otherwise the whole thing crashes
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

        let solutions_path = args.output_dir.join(PathBuf::from("crashes"));

        let solution_corpus =
            OnDiskCorpus::<BytesInput>::new(solutions_path).expect("Could not create crash corpus");

        // TODO: implement switch
        // if args.store_queue_to_disk{
        //     let queue_corpus = OnDiskCorpus::new(args.output_dir.join(PathBuf::from("queue")))
        //                 .expect("Could not create queue corpus");
        // } else {
        //     let queue_corpus = InMemoryCorpus::<BytesInput>::new();
        // }

        let queue_corpus = OnDiskCorpus::new(args.output_dir.join(format!("queue_{}", core_id)))
                .expect("Could not create queue corpus");
        // let queue_corpus = InMemoryCorpus::<BytesInput>::new();

        let mut state = state.unwrap_or_else(|| {StdState::new(
                StdRand::with_seed(current_nanos()),
                queue_corpus,
                solution_corpus,
                &mut feedback,
                &mut objective,
            ).unwrap()}
            );

        let prog_path = args.path_to_binary.to_owned();

        let fork_server = ForkserverExecutor::builder()
            .program(prog_path)
            .arg_input_file_std()
            .coverage_map_size(MAP_SIZE)
            .build(tuple_list!(edges_observer, time_observer))
            .unwrap();

        let timeout = Duration::from_secs(1);

        let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout).unwrap();

        let mutator1 = StdScheduledMutator::new(havoc_mutations());
        // TODO: Evaluate whether it makes sense to include two stages
        let mutator2 = StdScheduledMutator::new(tuple_list!(SpliceMutator::new()));
        let mut stages = tuple_list!(
            StdMutationalStage::new(mutator1),
            StdMutationalStage::new(mutator2)
        );

        let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        println!("We're a client on core {}, let's fuzz :)", core_id);

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

    // Save stats to disk every 60 seconds
    let stats = OnDiskTOMLMonitor::new(
        args.output_dir.join("stats.toml"),
        // MultiMonitor::new(|s| println!("{}", s))
        TuiMonitor::new(String::from("My Monitor"), true)
    );

    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new().
            expect("Failed to initialize shared memory for launcher"))
        .monitor(stats)
        // Let all fuzzing instances fuzzing the same binary use the same config for now.
        // Let's them exchange every input without needing to rerun it
        .configuration(EventConfig::from_name(args.path_to_binary.to_str().unwrap()))
        // .configuration(AlwaysUnique)
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
