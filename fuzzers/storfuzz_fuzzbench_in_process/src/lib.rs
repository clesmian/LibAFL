//! A singlethreaded libfuzzer-like fuzzer that can auto-restart.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use core::{cell::RefCell, time::Duration};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
};
use std::cmp::{max, min};
use std::env::{set_var, var};

use env_logger;

use clap::{Parser, CommandFactory, arg, ArgAction::Count};
use log::{LevelFilter, warn, info};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or, feedback_and_fast, feedback_not,
    feedbacks::{
        CrashFeedback,
        MaxMapFeedback,
        TimeFeedback,
        TimeoutFeedback,
        ConstFeedback,
        custom::CustomFeedback
    },
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::{SimpleMonitor, OnDiskTOMLMonitor},
    mutators::{
        scheduled::havoc_mutations, tokens_mutations,
        StdMOptMutator, Tokens,
    },
    observers::{HitcountsMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage,
    },
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};
use libafl::feedbacks::AflMapFeedback;
use libafl::observers::MultiMapObserver;
use libafl::prelude::MapFeedbackMetadata;
use libafl::state::HasNamedMetadata;
use libafl_bolts::{
    current_nanos,
    current_time,
    os::{dup, dup2},
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice,
    Named,
    SerdeAny};
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl_targets::autotokens;
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, std_storfuzz_map_observer,
    storfuzz_map_mut_slice, edges_map_mut_slice
};

#[cfg(feature = "storfuzz_introspection")]
use libafl_targets::__storfuzz_introspect;

use storfuzz_constants::DEFAULT_ASAN_OPTIONS;
use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize, SerdeAny)]
struct SerializableDuration{
    secs: u64,
    subsec_nanos: u32
}


#[derive(Debug, Serialize, Deserialize, SerdeAny, Copy, Clone)]
enum CoverageSelection { First, Second }


const METADATA_KEY: &str = "switch_metadata";
#[derive(Debug, Serialize, Deserialize, SerdeAny, Copy, Clone)]
struct SwitchMetadata {
    next_switch_at: u64,
    next_check_at: u64,
    target_coverage: u64,
    current_period: CoverageSelection
}

impl Into<Duration> for &SerializableDuration{
    fn into(self) -> Duration {
        Duration::from_secs(self.secs) + Duration::from_nanos(self.subsec_nanos as u64)
    }
}
impl Into<SerializableDuration> for Duration{
    fn into(self) -> SerializableDuration {
        SerializableDuration{ secs: self.as_secs(), subsec_nanos:self.subsec_nanos()}
    }
}

#[derive(Parser)]
#[derive(Debug)]
#[command(about = "An AFL-like fuzzer built for fuzzbench")]
struct Arguments {
    #[arg(short, long, value_name = "PATH")]
    input_dir: Option<PathBuf>,
    #[arg(short, long, value_name = "PATH")]
    output_dir: Option<PathBuf>,
    #[arg(short, long, default_value = "", value_name = "PATH", help = "Put '-' for stdout")]
    debug_logfile: String,
    #[arg(short, long, default_value_t=0, action=Count, help="Verbosity level")]
    verbose: u8,
    // TODO: reimplement
    // #[arg(long, default_value_t = false, help = "Do not evaluate coverage if we disregard it")]
    // fast_disregard: bool,
    #[arg(long, short, default_value_t = 1000, help = "Timeout value in milliseconds")]
    timeout: u64,
    #[arg(long, short = 'T', default_value_t = false, help = "Consider timeouts to be solutions")]
    timeouts_are_solutions: bool,
    #[cfg(not(feature = "keep-queue-in-memory"))]
    #[arg(long, short = 'm', default_value_t = false, help = "Store metadata of queue entries on disk")]
    store_queue_metadata: bool,
    #[arg(value_name = "FILE", long, short='x', help = "Token file as produced by autotokens pass")]
    tokenfile: Option<PathBuf>,
    #[arg(value_name = "SECONDS",long, short='l', default_value_t = 1, help = "Time in seconds between log entries, 0 signals no wait time")]
    secs_between_log_msgs: u64,
    #[arg(value_name = "SECONDS",long, default_value_t = 1800, help = "How much time does each fuzzer have to improve coverage")]
    improvement_time: u64,
    #[arg(value_name = "PERCENT",long, default_value_t = 20, help = "By how much must a fuzzer improve the adversary's coverage to be rated successful")]
    improvement_goal: u8,
    #[arg(long, default_value_t = false, help = "Start with edge coverage only. (Default: start with full coverage)")]
    start_with_edge_coverage: bool,
    #[arg()]
    remaining: Option<Vec<String>>
}

const SWITCHER_FEEDBACK_NAME: &str = "AdversarialCoverageFeedback";

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub extern "C" fn libafl_main() {
    let args = Arguments::parse();
    let stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd()).unwrap();
        File::from_raw_fd(new_fd)
    };

    let verbosity_numeric=
        min(
            if !args.debug_logfile.is_empty()
                { max(LevelFilter::Warn as u8, args.verbose) }
            else
                { args.verbose },
            LevelFilter::max() as u8
        );

    let verbosity = LevelFilter::iter().nth(verbosity_numeric as usize).unwrap();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(
            verbosity.as_str()
        )
    )
        .filter_module(SWITCHER_FEEDBACK_NAME, max(LevelFilter::Info, verbosity))
        .target(env_logger::Target::Pipe(Box::new(stdout_cpy)))// Use copy of stdout
        .write_style(env_logger::WriteStyle::Always)// Ensure that colors are printed
        .init();

    println!("{:#?}", args);

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    if let Some(filenames) = args.remaining {
        let filenames: Vec<&str> = filenames.iter().map(String::as_str).collect();
        if !filenames.is_empty() {
            run_testcases(&filenames);
            return;
        }
    }

    if args.output_dir.is_none() || args.input_dir.is_none() {
        let mut cmd =  Arguments::command();
        cmd.print_help().expect("Failed printing help. Something must be seriously wrong!");
        return;
    }

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = args.output_dir.unwrap();

    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }

    let stats_file = out_dir.clone().join("stats.toml");

    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = args.input_dir.unwrap();
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    match var("ASAN_OPTIONS") {
        Ok(options) => {println!("Using predefined ASAN_OPTIONS: {}", options)}
        Err(_) => {
            println!("Setting ASAN_OPTIONS to: {}", DEFAULT_ASAN_OPTIONS);
            set_var("ASAN_OPTIONS", DEFAULT_ASAN_OPTIONS);
        }
    }

    let timeout = Duration::from_millis(args.timeout);

    let log =
        if !args.debug_logfile.is_empty() {
            let debug_log_path = out_dir.clone().join(args.debug_logfile.clone()).to_str().unwrap().to_owned();
            Some(PathBuf::from(debug_log_path))
        } else {
            None
        };

    let secs_between_log_msgs = Duration::from_secs(args.secs_between_log_msgs);

    fuzz(out_dir,
         crashes,
         &in_dir,
         args.tokenfile,
         log,
         secs_between_log_msgs,
         stats_file,
         timeout,
         args.timeouts_are_solutions,
         // args.fast_disregard, // TODO: re-enable once implemented
         args.store_queue_metadata,
         args.start_with_edge_coverage,
         args.improvement_time,
         args.improvement_goal)
        .expect("An error occurred while fuzzing");
}

fn run_testcases(filenames: &[&str]) {
    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    println!(
        "You are not fuzzing, just executing {} testcases",
        filenames.len()
    );
    for fname in filenames {
        println!("Executing {fname}");

        let mut file = File::open(fname).expect("No file found");
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).expect("Buffer overflow");

        libfuzzer_test_one_input(&buffer);
    }
}

/// The actual fuzzer
#[allow(clippy::too_many_lines)]
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: &PathBuf,
    tokenfile: Option<PathBuf>,
    logfile: Option<PathBuf>,
    secs_between_log_msgs: Duration,
    stats_file: PathBuf,
    timeout: Duration,
    timeouts_are_solutions: bool,
    // fast_disregard: bool, // TODO: re-enable once implemented
    store_queue_metadata: bool,
    start_with_edge_coverage: bool,
    improvement_time: u64,
    improvement_goal_pct: u8
) -> Result<(), Error> {

    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    let file_null = File::open("/dev/null")?;

    let log = match logfile.clone() {
        Some(logfile_path) => RefCell::new(OpenOptions::new().append(true).create(true).open(logfile_path)?),
        None => RefCell::new(OpenOptions::new().append(true).open("/dev/null")?)
    };

    // Initialize in the past to ensure immediate first log message
    let mut last_log_event = current_time() - secs_between_log_msgs - Duration::from_secs(1);

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = OnDiskTOMLMonitor::new(
        stats_file,
        SimpleMonitor::with_user_monitor(
            |s| {
                if secs_between_log_msgs.is_zero() || last_log_event + secs_between_log_msgs < current_time() {
                    last_log_event = current_time();
                    #[cfg(feature = "storfuzz_introspection")]
                    {
                        let storfuzz_stats = unsafe { __storfuzz_introspect() };
                        writeln!(&mut stdout_cpy, "{s}, total_stores:{}, skipped_stores:{}", storfuzz_stats.total_count, storfuzz_stats.count_skipped).unwrap();
                        writeln!(log.borrow_mut(), "{:?} {s}, total_stores:{}, skipped_stores:{}", current_time(), storfuzz_stats.total_count, storfuzz_stats.count_skipped).unwrap();
                    }
                    #[cfg(not(feature = "storfuzz_introspection"))]{
                        writeln!(&mut stdout_cpy, "{s}").unwrap();
                        writeln!(log.borrow_mut(), "{:?} {s}", current_time()).unwrap();
                    }
                }
            },
            true
        )
    );

    // We need a shared map to store our state before a crash.
    // This way, we are able to continue fuzzing afterwards.
    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                println!("Shutting down, there could be some additional fuzzer output");
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };

    // Create an observation channel using the coverage map
    // We don't use the hitcounts (see the Cargo.toml, we use pcguard_edges)
    let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") });
    let data_observer = unsafe {std_storfuzz_map_observer("data")};
    let calibration_observer = MultiMapObserver::new("calibration",
                                                     unsafe {
                                                         vec!{edges_map_mut_slice(), storfuzz_map_mut_slice()}
                                                     });

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let edge_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);
    let mut data_feedback = AflMapFeedback::tracking(&data_observer, true, false);
    data_feedback.set_is_bitmap(true);
    let data_feedback = data_feedback;

    let data_feedback_name = data_feedback.name().to_owned();
    let edges_feedback_name = edge_feedback.name().to_owned();

    let calibration_feedback = AflMapFeedback::new(&calibration_observer);
    let calibration_stage = CalibrationStage::new(&calibration_feedback);

    let use_data_in_first_period = !start_with_edge_coverage;
    let is_it_time_for_data_feedback = CustomFeedback::new(
        SWITCHER_FEEDBACK_NAME, |state: &mut StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>| -> bool {
            if state.must_load_initial_inputs(){
                // We are not finished loading initial inputs. Return initial state
                return use_data_in_first_period;
            }

            let map_period_to_coverage = |period: CoverageSelection| {
              match period {
                  CoverageSelection::First => {if use_data_in_first_period {"data"} else {"edge"}}
                  CoverageSelection::Second => {if use_data_in_first_period {"edge"} else {"data"}}
              }
            };

            let map_period_to_adversarial_metric = |period: CoverageSelection| {
                match period {
                    CoverageSelection::First => {if use_data_in_first_period {"edge"} else {"data"}}
                    CoverageSelection::Second => {if use_data_in_first_period {"data"} else {"edge"}}
                }
            };


            let improvement_time = improvement_time;
            let improvement_factor = (100 + improvement_goal_pct) as f64 / 100f64;

            let meta = match state.named_metadata::<SwitchMetadata>(METADATA_KEY) {
                Ok(t) => {
                    *t
                },
                Err(_) => {
                    let map_fill =
                        if use_data_in_first_period {
                            state
                                .named_metadata_map()
                                .get::<MapFeedbackMetadata<u8>>(edges_feedback_name.as_str())
                                .unwrap().num_covered_map_indexes
                        } else {
                            state
                                .named_metadata_map()
                                .get::<MapFeedbackMetadata<u8>>(data_feedback_name.as_str())
                                .unwrap().num_covered_map_indexes
                        };
                    warn!(target: SWITCHER_FEEDBACK_NAME, "Initializing metadata object in state");
                    let new_meta = SwitchMetadata {
                        next_switch_at: current_time().as_secs() + improvement_time, // Give half an hour as a start
                        current_period: CoverageSelection::First,
                        target_coverage: (map_fill as f64 * improvement_factor) as u64,
                        next_check_at: 0
                    };
                    info!(target: SWITCHER_FEEDBACK_NAME, "Starting with {} coverage. Initial target: {} entries in {} map",
                        map_period_to_coverage(new_meta.current_period),
                        new_meta.target_coverage,
                        map_period_to_adversarial_metric(new_meta.current_period)
                    );
                    state.add_named_metadata(
                        METADATA_KEY,
                        new_meta,
                    );
                    new_meta
                }
            };

            // It is not time to switch yet
            if meta.next_switch_at > current_time().as_secs(){
                return match meta.current_period {
                    CoverageSelection::First => use_data_in_first_period,
                    CoverageSelection::Second => !use_data_in_first_period
                }
            }

            let map_fill =
                if ( use_data_in_first_period && matches!(meta.current_period, CoverageSelection::First) ) ||
                    ( !use_data_in_first_period && matches!(meta.current_period, CoverageSelection::Second) ){
                    state
                        .named_metadata_map()
                        .get::<MapFeedbackMetadata<u8>>(edges_feedback_name.as_str())
                        .unwrap().num_covered_map_indexes as u64
                } else {
                    state
                        .named_metadata_map()
                        .get::<MapFeedbackMetadata<u8>>(data_feedback_name.as_str())
                        .unwrap().num_covered_map_indexes as u64
                } ;
            // Assume we want to switch
            let mut switch = true;

            // We don't want to switch if the target has been reached
            if map_fill >= meta.target_coverage {
                switch = false;
            }

            let new_target =
                ( if switch {
                    // Get the coverage for our current optimization target
                    if ( use_data_in_first_period && matches!(meta.current_period, CoverageSelection::First) ) ||
                        ( !use_data_in_first_period && matches!(meta.current_period, CoverageSelection::Second) ){
                        state
                            .named_metadata_map()
                            .get::<MapFeedbackMetadata<u8>>(data_feedback_name.as_str())
                            .unwrap().num_covered_map_indexes as u64
                    } else {
                        state
                            .named_metadata_map()
                            .get::<MapFeedbackMetadata<u8>>(edges_feedback_name.as_str())
                            .unwrap().num_covered_map_indexes as u64
                    }
                } else {
                    // Keep using the coverage for the adversarial optimization target
                    map_fill
                }  as f64 * improvement_factor ) as u64;

            let next_period = if switch {
                match meta.current_period {
                    CoverageSelection::First => { CoverageSelection::Second }
                    CoverageSelection::Second => { CoverageSelection::First }
                }
            } else {
                meta.current_period
            };

            state.add_named_metadata(
                METADATA_KEY,
                SwitchMetadata{
                    next_switch_at: current_time().as_secs() + improvement_time,
                    next_check_at: 0,
                    target_coverage: new_target,
                    current_period: next_period
                },
            );

            if switch {
                info!(target: SWITCHER_FEEDBACK_NAME, "Missed target {}/{} ({:.2}%), switching to {} coverage. New target: {} entries in {} map",
                    map_fill,
                    meta.target_coverage,
                    (map_fill as f64/ meta.target_coverage as f64) * 100f64,
                    map_period_to_coverage(next_period),
                    new_target,
                    map_period_to_adversarial_metric(next_period)
                );
            } else {
                info!(target: SWITCHER_FEEDBACK_NAME, "Reached target {}/{} ({:.2}%), continuing with {} coverage. New target: {} entries in {} map",
                    map_fill,
                    meta.target_coverage,
                    (map_fill as f64/ meta.target_coverage as f64) * 100f64,
                    map_period_to_coverage(next_period),
                    new_target,
                    map_period_to_adversarial_metric(next_period)
                );
            }

            return match next_period {
                CoverageSelection::First => {use_data_in_first_period}
                CoverageSelection::Second => {!use_data_in_first_period}
            };
        }
    );

    let mut feedback = feedback_or!(
        feedback_and_fast!(
            edge_feedback,
            feedback_not!(is_it_time_for_data_feedback.clone())
        ),
        feedback_and_fast!(
            data_feedback,
            is_it_time_for_data_feedback
        ),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or!(
        CrashFeedback::new(),
        feedback_and_fast!(ConstFeedback::new(timeouts_are_solutions), TimeoutFeedback::new())
    );

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            if store_queue_metadata{
                InMemoryOnDiskCorpus::new(corpus_dir).unwrap()
            } else {
                InMemoryOnDiskCorpus::no_meta(corpus_dir).unwrap()
            },
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    println!("Let's fuzz :)");

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    let power = StdPowerMutationalStage::new(mutator);

    // Ensure that combined_feedback is present in the metadata map of the state
    state.add_named_metadata(
        &*calibration_feedback.name().to_string(),
        // Doesn't really matter as it is overwritten anyways
        MapFeedbackMetadata::<u8>::new(0),
    );

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
        &mut state,
        &calibration_observer,
        Some(PowerSchedule::FAST),
    ));

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        libfuzzer_test_one_input(buf);
        ExitKind::Ok
    };


    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor =
        InProcessExecutor::with_timeout(
            &mut harness,
            tuple_list!(edges_observer, data_observer, calibration_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout
        )?;

    // The order of the stages matter!
    let mut stages = tuple_list!(calibration_stage, power);

    // Read tokens
    if state.metadata_map().get::<Tokens>().is_none() {
        let mut toks = Tokens::default();
        if let Some(tokenfile) = tokenfile {
            toks.add_from_file(tokenfile)?;
        }
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        {
            toks += autotokens()?;
        }

        if !toks.is_empty() {
            state.add_metadata(toks);
        }
    }

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap();
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // Remove target ouput (logs still survive)
    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        if !var("LIBAFL_FUZZBENCH_DEBUG").is_ok() {
            dup2(null_fd, io::stdout().as_raw_fd())?;
            dup2(null_fd, io::stderr().as_raw_fd())?;
        }
    }
    // reopen file to make sure we're at the end
    if logfile.is_some() {
        log.replace(OpenOptions::new().append(true).create(true).open(logfile.unwrap())?);
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    // Never reached
    Ok(())
}
