// Adapted from afl-coverage-pass.cc

#include "common-llvm.h"

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
  #include <unistd.h>
  #include <sys/time.h>
#else
  #include <io.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <list>
#include <string>
#include <fstream>

#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/FormatVariadic.h"

// Without this, Can't build with llvm-14 & old PM
#if LLVM_VERSION_MAJOR >= 14 && !defined(USE_NEW_PM)
  #include "llvm/Pass.h"
#endif

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/CFG.h"
#else
  #include "llvm/DebugInfo.h"
  #include "llvm/Support/CFG.h"
#endif

#define DATA_MAP_SIZE STORFUZZ_MAP_SIZE

using namespace llvm;

// To enable: Add `-mllvm --debug_storfuzz_coverage` to cmd-line
static cl::opt<bool> Debug("debug_storfuzz_coverage", cl::desc("Debug prints"),
                           cl::init(false), cl::NotHidden);
std::mutex(logMutex);
bool logToFile = true;
std::ofstream *logFile = nullptr;

static void log(std::string prefix,std::string msg,bool multiline_msg = false){
  if(logToFile){
    logToFile = getenv("STORFUZZ_LOG_TO_FILE") != nullptr;
    if(__glibc_unlikely(!logToFile)){
      return;
    }

    if(!multiline_msg){
      // Remove occasional newlines
      erase_if(msg, [](char x) { return x == '\n' ;});
    }

    auto complete_msg = prefix.append(" | ").append(msg);

    {
      std::unique_lock<std::mutex> lock(logMutex);
      if (__glibc_unlikely(logFile == nullptr)) {
        char       *file_base = getenv("STORFUZZ_LOG_TO_FILE");
        std::string logFileName =
            file_base + std::string("_") + std::to_string(getpid()) + ".txt";
        logFile = new std::ofstream(logFileName, std::ios_base::app);
      }
      *logFile << std::unitbuf << complete_msg << std::endl;
    }

  }
}

namespace {

#ifdef USE_NEW_PM
class StorFuzzCoverage : public PassInfoMixin<StorFuzzCoverage> {
 public:
  StorFuzzCoverage() {
#else
class StorFuzzCoverage : public ModulePass {
 public:
  static char            ID;
  static llvm::StringRef name() {
    return "StorFuzzCoverage";
  }
  StorFuzzCoverage() : ModulePass(ID) {
#endif
  }

#ifdef USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  uint32_t map_size = DATA_MAP_SIZE;
  uint32_t function_minimum_size = 1;

  bool getInsertionPointInSameBB(Instruction          *start,
                                 BasicBlock::iterator &insertionPoint) {
    BasicBlock *insertionBB = start->getParent();
    insertionPoint = start->getIterator();
    BasicBlock::const_iterator End = insertionBB->end();
    // Safeguard against infinite loops due to logic errors on my side
    int i = 0;

    // Ensure that we are not already at the end of the BB
    if (insertionPoint == End) { return false; }
    ++insertionPoint;
    while (insertionPoint != End && i < insertionBB->size()) {
      if (!isa<PHINode>(*insertionPoint) && !insertionPoint->isEHPad()) {
        return true;
      } else if (insertionBB->isEntryBlock()) {
        while (insertionPoint != End && i < insertionBB->size() &&
               (isa<AllocaInst>(*insertionPoint) ||
                isa<DbgInfoIntrinsic>(*insertionPoint) ||
                isa<PseudoProbeInst>(*insertionPoint))) {
          if (const AllocaInst *AI = dyn_cast<AllocaInst>(&*insertionPoint)) {
            if (!AI->isStaticAlloca()) break;
          }
          i++;
        }
        return true;
      }
      insertionPoint++;
      i++;
    }
    if (i >= insertionBB->size()) {
      errs() << "ERROR: We have exceeded the size of the BB. The question is why?\n";
      errs() << "Start instr: " << start;
      errs() << "Insertion BB: " << insertionBB;
      return false;
    }
    if (insertionPoint == End) {
      return false;
    } else {
      return true;
    }
  }

  /* Function that we never instrument or analyze */
  /* Copied from cmplog pass */
  bool isIgnoreFunction(const llvm::Function *F) {
    // Starting from "LLVMFuzzer" these are functions used in libfuzzer based
    // fuzzing campaign installations, e.g. oss-fuzz

    static constexpr const char *ignoreList[] = {

        "asan.",
        "llvm.",
        "sancov.",
        "__ubsan",
        "ign.",
        "__afl",
        "_fini",
        "__libc_",
        "__asan",
        "__msan",
        "__cmplog",
        "__sancov",
        "__san",
        "__cxx_",
        "__decide_deferred",
        "_GLOBAL",
        "_ZZN6__asan",
        "_ZZN6__lsan",
        "msan.",
        "LLVMFuzzerM",
        "LLVMFuzzerC",
        "LLVMFuzzerI",
        "maybe_duplicate_stderr",
        "discard_output",
        "close_stdout",
        "dup_and_close_stderr",
        "maybe_close_fd_mask",
        "ExecuteFilesOnyByOne",

    };

    for (auto const &ignoreListFunc : ignoreList) {
      if (F->getName().startswith(ignoreListFunc)) { return true; }
    }

    static constexpr const char *ignoreSubstringList[] = {

        "__asan",       "__msan",     "__ubsan", "__lsan",
        "__san",        "__sanitize", "__cxx",   "_GLOBAL__",
        "DebugCounter", "DwarfDebug", "DebugLoc"

    };

    for (auto const &ignoreListFunc : ignoreSubstringList) {
      // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
      if (StringRef::npos != F->getName().find(ignoreListFunc)) { return true; }
    }

    return false;
  }

  static bool isSmallConstantAdditionOrSubtraction(Instruction* instr,
                                                   uint64_t smallConstant = 2){
    if(instr->getOpcode() == Instruction::Add ||
        instr->getOpcode() == Instruction::Sub) {
      for (auto op : instr->operand_values()) {
        if (isa<ConstantInt>(op) &&
            (cast<ConstantInt>(op)->getValue().abs().ule(smallConstant))) {
          return true;
        }
      }
    }
    return false;
  }

  // Weaken functions if requested (code by tholl)
  void maybeWeakenFunction(Module &M, Function &F){
    // This is pretty dumb. There must be a better way to check potentially multiple strings
    StringSet WeakenFunctions;
    WeakenFunctions.insert("main");

    if (WeakenFunctions.contains(F.getName())) {
      auto PreviousLinkage = F.getLinkage();
      std::string PreviousLinkageDescription = "";
      switch (PreviousLinkage) {
        // Appending linkage cannot be merged
        case GlobalValue::LinkageTypes::AppendingLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName() << ", symbol has appending linkage\n";
          break;
          // These are weaker or equivalent to WeakAnyLinkage
        case GlobalValue::LinkageTypes::InternalLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName() << ", symbol already has internal linkage\n";
          break;
        case GlobalValue::LinkageTypes::PrivateLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName() << ", symbol already has private linkage\n";
          break;
        case GlobalValue::LinkageTypes::AvailableExternallyLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName() << ", symbol is already marked as 'available externally'\n";
          break;
        case GlobalValue::LinkageTypes::WeakAnyLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName() << ", symbol is already marked as weak\n";
          break;
        case GlobalValue::LinkageTypes::LinkOnceAnyLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName() << ", symbol is already marked as link-once\n";
          break;
        case GlobalValue::LinkageTypes::ExternalWeakLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName() << ", symbol is already marked as weak and extern\n";
          break;
        case GlobalValue::LinkageTypes::CommonLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName() << ", function is marked as common (this should not be possible!)\n";
          break;
          // These must be weakened.
        case GlobalValue::LinkageTypes::ExternalLinkage:
          PreviousLinkageDescription = "external";
          break;
        case GlobalValue::LinkageTypes::LinkOnceODRLinkage:
          PreviousLinkageDescription = "link-once (ODR)";
          break;
        case GlobalValue::LinkageTypes::WeakODRLinkage:
          PreviousLinkageDescription = "weak (ODR)";
          break;
      }
      if (!PreviousLinkageDescription.empty()) {
        errs() << "Dropping linkage of " << F.getName() << " in " << M.getName() << " from " << PreviousLinkageDescription << " to weak linkage\n";
        F.setLinkage(GlobalValue::LinkageTypes::WeakAnyLinkage);
        GlobalAlias::create(F.getType(), /* AddrSpace = */ 0, PreviousLinkage, "__storfuzz_original_" + F.getName(), &F, &M);
      }
    }
  }


  // Value.printNameOrAsOperand is only available in debug builds
  std::string printNameOrAsOperandInRelease(Value* value, Module* M = nullptr, bool printType = true){
    assert(value != nullptr);
    if (!value->getName().empty())
      return std::string(value->getName());

    std::string BBName;
    raw_string_ostream OS(BBName);
    value->printAsOperand(OS, printType, M);
    return OS.str();
  }
};

}  // namespace

#ifdef USE_NEW_PM
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "StorFuzzCoverage", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {
  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(StorFuzzCoverage());
                });

            // Allow for testing with opt
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "StorFuzzCoverage") {
                    MPM.addPass(StorFuzzCoverage());
                    return true;
                  }
                  return false;
                });
          }};
}
#else

char StorFuzzCoverage::ID = 1;
#endif

#ifdef USE_NEW_PM
PreservedAnalyses StorFuzzCoverage::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool StorFuzzCoverage::runOnModule(Module &M) {
#endif
  if (getenv("CONFIGURE_MODE")) {
    errs() << "WARNING: CONFIGURE_MODE, not doing anything\n";
#ifdef USE_NEW_PM
    return PreservedAnalyses::all();
#else
    return true;
#endif
  }

  LLVMContext &C = M.getContext();

  Type *VoidTy = Type::getVoidTy(C);

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  Type        *Int8PtrTy = PointerType::getUnqual(IntegerType::getInt8Ty(C));
  Type        *Int16PtrTy = PointerType::getUnqual(IntegerType::getInt16Ty(C));
  Type        *Int32PtrTy = PointerType::getUnqual(IntegerType::getInt32Ty(C));
  Type        *Int64PtrTy = PointerType::getUnqual(IntegerType::getInt64Ty(C));
  Type *Int128PtrTy = PointerType::getUnqual(IntegerType::getInt128Ty(C));

  uint32_t     rand_seed;
  unsigned int cur_loc = 0;

#ifdef USE_NEW_PM
  auto PA = PreservedAnalyses::none();
  // See here:
  // https://github.com/AFLplusplus/AFLplusplus/blob/358cd1b062e58ce1d5c8efeef4789a5aca7ac5a9/instrumentation/SanitizerCoveragePCGUARD.so.cc#L236

  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
#else
  errs() << "WARNING: without new pass manager, we do not support certain analyses!\n";
#endif

  /* Setup random() so we get Actually Random(TM) */
  rand_seed = time(NULL);
  srand(rand_seed);

  GlobalVariable *StorFuzzMapPtr = new GlobalVariable(
      M, PointerType::getUnqual(Int8Ty), false,
      GlobalValue::ExternalWeakLinkage, nullptr, "__storfuzz_area_ptr");

  // other constants we need
  ConstantInt *Mask[8] = {
      ConstantInt::get(Int8Ty, 1 << 0), ConstantInt::get(Int8Ty, 1 << 1),
      ConstantInt::get(Int8Ty, 1 << 2), ConstantInt::get(Int8Ty, 1 << 3),
      ConstantInt::get(Int8Ty, 1 << 4), ConstantInt::get(Int8Ty, 1 << 5),
      ConstantInt::get(Int8Ty, 1 << 6), ConstantInt::get(Int8Ty, 1 << 7)};

  /* Instrument all the things! */

  int inst_stores = 0;
  // scanForDangerousFunctions(&M);

  Type          *argTypes[] = {Int32Ty, Int8Ty, Int64Ty};
  FunctionType  *coverageFuncType = FunctionType::get(VoidTy, argTypes, false);
  FunctionCallee coverageFunc =
      M.getOrInsertFunction("__storfuzz_record_value", coverageFuncType);

  Type          *aggregate_argTypes[] = {Int8Ty, Int64Ty};
  FunctionType  *aggregate_FuncType = FunctionType::get(VoidTy, aggregate_argTypes, false);
  FunctionCallee aggregate_func =
      M.getOrInsertFunction("__storfuzz_aggregate_value", aggregate_FuncType);

  Type          *store_aggregated_argTypes[] = {Int16Ty, Int8Ty};
  FunctionType  *store_aggregated_FuncType = FunctionType::get(VoidTy, store_aggregated_argTypes, false);
  FunctionCallee store_aggregated_Func =
      M.getOrInsertFunction("__storfuzz_store_aggregated_value", store_aggregated_FuncType);


  // Useful for BBs with only one store
  // __storfuzz_store_single_aggregated_value(uint16_t bb_id, uint8_t bitmask, uint64_t value){
  Type          *store_single_aggregated_argTypes[] = {Int16Ty, Int8Ty, Int64Ty};
  FunctionType  *store_single_aggregated_FuncType = FunctionType::get(VoidTy, store_single_aggregated_argTypes, false);
  FunctionCallee store_single_aggregated_Func =
      M.getOrInsertFunction("__storfuzz_store_single_aggregated_value", store_single_aggregated_FuncType);

  // Threshold used to determine whether a bb should be instrumented
  auto THRESHOLD = 0;
  if(getenv("MAX_STORES_PER_BB")) {
    THRESHOLD = atoi(getenv("MAX_STORES_PER_BB"));
  }
  if(THRESHOLD <= 0){
    THRESHOLD = 9; // Default to 9
  }


  for (auto &F : M) {


    maybeWeakenFunction(M, F);
    if (Debug)
      errs() << "FUNCTION: " << F.getName() << " size=" << F.size() << "\n";
    if (isIgnoreFunction(&F)) {
      if (Debug)
        errs() << "Ignoring function " << F.getName() << "\n";
      continue;
    }

    // Bail out quickly
    if (F.onlyReadsMemory()){
      errs() << "FUNCTION: " << F.getName() << " does not write to memory\n";
      continue;
    }


    if (F.size() < function_minimum_size) { continue; }
#ifdef USE_NEW_PM
    auto *LVI = &FAM.getResult<LazyValueAnalysis>(F);
    auto *LoopInfo = &FAM.getResult<LoopAnalysis>(F);

#endif

    for (auto &BB : F) {
      BasicBlock::iterator insertionPoint = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*insertionPoint));

      uint16_t BB_store_count = 0;

      // Needed only for ONE_INSTRUMENTATION_PER_BB
      Value   *BB_id;
      BB_id = ConstantInt::get(Int16Ty, (uint16_t) RandBelow(map_size));
      uint32_t BB_bitmask_selector = RandBelow(8);
      bool only_one_store = false;

      bool instrument_this_time = false;
      // Pass over each block twice and only instrument it when it has fewer than <THRESHOLD> stores
      do { // while (!instrument_this_time)
        // If we have found stores already we're in the second pass. The THRESHOLD has been checked in the first iteration
        if (BB_store_count > 0){
          instrument_this_time = true;

          // We can maybe optimize a bit more
          if(BB_store_count == 1){
            only_one_store = true;
          }

          // Reset for reuse as counter
          BB_store_count = 0;
        }

        // Ensure we only log stuff once
        bool log_this_time = !instrument_this_time;

        for (auto &instr : BB) {
          StoreInst *storeInst;
          if ((storeInst = dyn_cast<StoreInst>(&instr))) {
            // Check that this instruction is not already part of AFL
            // instrumentation
            if (storeInst->getMetadata("nosanitize") != nullptr) continue;

            // Don't instrument stores to alloca'd locations
            Value *storeLocation = storeInst->getPointerOperand();
            if (!(dyn_cast<AllocaInst>(storeLocation))) {
              Value *storedValue;
              storedValue = storeInst->getValueOperand();

              Instruction *valueDefInstruction;
              // If the stored value does not stem from an instruction it is not
              // interesting
              // Ensure valueDefInstruction is exactly the SSA Value stored by storeInst
              if (!(valueDefInstruction =
                        dyn_cast<Instruction>(storedValue)))
                continue;

              IntegerType *storedType;
              if ((storedType =
                       dyn_cast<IntegerType>(storedValue->getType()))) {

                // Try to get the value before the cast, if the stored value
                // does not stem from an instruction it is not interesting
                Instruction* actual_valueDefInstruction = valueDefInstruction;
                Value* actual_storedValue = storedValue;
                bool skip = false;
                while (!skip) {
                  if (!(actual_valueDefInstruction =
                            dyn_cast<Instruction>(actual_storedValue))){
                    skip = true;
                    break;
                  } else if (actual_valueDefInstruction->isCast()) {
                    Instruction *castInstruction;
                    assert((castInstruction =
                                dyn_cast<CastInst>(actual_valueDefInstruction)));

                    // Get the value before the cast
                    actual_storedValue =
                        castInstruction->getOperand(0);

                    if (log_this_time) {
                      std::string        msg;
                      raw_string_ostream msg_stream(msg);

                      msg_stream << "\"" << *actual_storedValue << "\" | \""
                                 << *castInstruction << "\"";
                      log("UNCASTED", msg);
                    }
                  } else {
                    break;
                  }
                }
                if(skip)
                  continue;

                if (isa<LoadInst, VAArgInst>(actual_valueDefInstruction)){
                  if(log_this_time) {
                    std::string        msg;
                    raw_string_ostream msg_stream(msg);

                    msg_stream << "\"" << actual_valueDefInstruction->getOpcodeName() << "\" | \"" <<
                        *actual_valueDefInstruction << "\" | \"";
                    if (valueDefInstruction != actual_valueDefInstruction){
                      msg_stream << *valueDefInstruction;
                    }
                    msg_stream << "\"";

                    log("SKIPPED", msg);
                  }
                  continue;
                } else if(isSmallConstantAdditionOrSubtraction(actual_valueDefInstruction)){
                  bool is_loop_ctr = false;
#ifdef USE_NEW_PM
                  auto loop = LoopInfo->getLoopFor(actual_valueDefInstruction->getParent());

                  while(loop && !is_loop_ctr){
                    auto cmp_instr = loop->getLatchCmpInst();
                    if (cmp_instr){
                      for(auto val: cmp_instr->operand_values()){
                        if(isa<Instruction>(val)){
                          // Easy case
                          if (val == actual_storedValue ||
                              val == storeLocation ||
                              val == storedValue) {
                            is_loop_ctr = true;
                          }
                          // Allow for one level of indirection
                          for(auto indirect_val : cast<Instruction>(val)->operand_values()) {
                            if (indirect_val == actual_storedValue ||
                                indirect_val == storeLocation ||
                                indirect_val == storedValue) {
                              is_loop_ctr = true;
                              break;
                            }
                          }
                          if(is_loop_ctr)
                            break;
                        }

                      }
                    }

                    loop = loop->getParentLoop();
                  }


                  if(is_loop_ctr) {
                    // FIXME: This detection is not complete!
                    // We miss many loop counters
                    if (log_this_time) {
                      std::string        msg;
                      raw_string_ostream msg_stream(msg);

                      msg_stream << "\""
                                 << actual_valueDefInstruction->getOpcodeName()
                                 << "\" | \"" << *actual_valueDefInstruction
                                 << "\" | \"";
                      if (valueDefInstruction != actual_valueDefInstruction) {
                        msg_stream << *valueDefInstruction;
                      }
                      msg_stream << "\"";

                      log("SKIPPED_LOOP_CTR", msg);
                    }
                    continue;
                  }
#endif
                }

                // If the type we started casting from, was not an integer, we don't want it
                IntegerType *actual_storedType;
                if(!(actual_storedType = dyn_cast<IntegerType>(actual_storedValue->getType()))){
                  // Include a message in the output, if the type of the value
                  // before casting is fundamentally different from the type
                  // after casting
                  if(((bool) actual_storedType) ^ ((bool) storedType) && log_this_time){
                    std::string        msg;
                    raw_string_ostream msg_stream(msg);

                    msg_stream << "\"" << *actual_storedValue->getType() << "\" | \"" <<
                        *storedValue->getType() << "\"";
                    log("TYPE_DISAGREEMENT", msg);
                  }
                  continue;
                }

                if (getenv("STORFUZZ_VERBOSE")) {
                  errs() << "BB: " << BB << "\n";
                  errs() << "Stored value: " << *storedValue << "\n";
                  errs() << "Store instruction: " << *storeInst << "\n";
                }


                if(log_this_time) {
                  std::string        msg;
                  raw_string_ostream msg_stream(msg);

                  if(isa<CallInst,InvokeInst>(actual_valueDefInstruction)){
                    CallBase* callInst = cast<CallBase>(actual_valueDefInstruction);

                    msg_stream << "\""
                               << actual_valueDefInstruction->getOpcodeName()
                               << "\" | \"";
                    if(callInst->getCalledFunction() && callInst->getCalledFunction()->hasName()){
                      msg_stream << callInst->getCalledFunction()->getName();
                    } else {
                      msg_stream << *callInst;
                    }
                    msg_stream << "\" | \"" << *actual_valueDefInstruction
                               << "\" | \"" ;
                    if (valueDefInstruction != actual_valueDefInstruction){
                      msg_stream << *valueDefInstruction;
                    }
                    msg_stream <<"\"";

                    log("INSTRUMENT_RETURN_VALUE", msg);
                  } else {
                    msg_stream << "\""
                               << actual_valueDefInstruction->getOpcodeName()
                               << "\" | \"" << *actual_valueDefInstruction
                               << "\" | \"" ;
                    if (valueDefInstruction != actual_valueDefInstruction){
                      msg_stream << *valueDefInstruction;
                    }
                    msg_stream << "\"";
                    log("INSTRUMENT_VALUE", msg);
                  }
                }

#ifdef USE_NEW_PM
                // Some logging of known value ranges
                auto valRange = LVI->getConstantRange(storedValue, storeInst, true);
                if(log_this_time){
                  std::string msg;
                  raw_string_ostream msg_stream(msg);

                  msg_stream << "\""
                             << *storeLocation << " (" << printNameOrAsOperandInRelease(storeLocation, &M, true) << ")\" | \""
                             << *storedValue << "\" | \""
                             << valRange << "\" | \""
                  // Some info on the value type and range
                             << *storedType <<
                      (LVI->getConstant(storedValue, storeInst) != nullptr ? " constant":
                             valRange.isWrappedSet() ? " wrapped":
                             valRange.isSignWrappedSet() ? " sign_wrapped" :
                             valRange.isUpperWrapped() ? " upper_wrapped":
                             valRange.isUpperSignWrapped() ? " upper_sign_wrapped" :
                                                         "") << "\" | ";

                  if(valRange.isFullSet()){
                    msg_stream << storedType->getBitMask();
                  } else {
                    auto size = (valRange.getUpper() - valRange.getLower())
                        .tryZExtValue();
                    if (size) {
                      msg_stream << size;
                    } else {
                      // Unknown error
                      errs() << "ERROR: Could not compute size for range: " << valRange << "\n";
                      msg_stream << "?";
                    }
                  }


                  log("VAL_RANGES", msg);
                }
#endif

                Value   *CurLoc;
                uint32_t bitmask_selector;

                // Handle phi node as store_location (stores to different locations are considered seperately)
                auto storeLocationToID = DenseMap<Value *, ConstantInt *>(4);

                // We only ever change anything in the second pass
                if(!instrument_this_time) {
                  if ((isa<PHINode>(storeLocation))) {
                    PHINode *storeLocationPhi = dyn_cast<PHINode>(storeLocation);
                    for (uint32_t i = 0; i < storeLocationPhi->getNumIncomingValues(); i++) {

                      // Use as a simple set, we only care about the number of different store locations
                      auto curLocIDIter = storeLocationToID.find(storeLocationPhi->getIncomingValue(i));
                      if (curLocIDIter == storeLocationToID.end()) {
                        storeLocationToID.insert(
                            std::pair<Value *, ConstantInt *>(
                                storeLocationPhi->getIncomingValue(i), nullptr));
                        BB_store_count++;
                      } // If we did not record the store location yet
                    } // For incoming value in store location phi node
                  } // ! instrument_this_time && is_phi_node
                  else { // ! instrument_this_tume && ! is_phi_node
                    BB_store_count++;
                  }
                } else { // If instrument_this_time
                  if ((isa<PHINode>(storeLocation))) {
                    PHINode *storeLocationPhi = dyn_cast<PHINode>(storeLocation);
                    insertionPoint = storeLocationPhi->getIterator();
                    while (insertionPoint !=
                           storeLocationPhi->getParent()->end() &&
                           isa<PHINode>(*insertionPoint)) {
                      insertionPoint++;
                    }
                    assert(insertionPoint !=
                           storeLocationPhi->getParent()->end());
                    IRB.SetInsertPoint(storeLocationPhi->getParent(),
                                       insertionPoint);

                    PHINode *CurLocPhi = IRB.CreatePHI(
                        // If we use ONE_INSTRUMENTATION_PER_BB, the current location id is only 8 bit
                        getenv("ONE_INSTRUMENTATION_PER_BB") != nullptr ? Int8Ty
                                                                        : Int32Ty,
                        storeLocationPhi->getNumIncomingValues());
                    for (uint32_t i = 0;
                         i < storeLocationPhi->getNumIncomingValues(); i++) {
                      // E.g.:
                      // %x.sink30 = phi ptr [ @x, %sw.bb9 ], [ @x, %sw.bb7 ], [ @y, %sw.bb6 ], [ @y, %while.body ] %74 = phi i32 [ 12312, %sw.bb9 ], [ 12312, %sw.bb7 ], [ 45645, %sw.bb6 ], [ 45645, %while.body ]
                      ConstantInt *curLocID;
                      auto         curLocIDIter = storeLocationToID.find(
                          storeLocationPhi->getIncomingValue(i));
                      if (curLocIDIter == storeLocationToID.end()) {
                        if (getenv("ONE_INSTRUMENTATION_PER_BB") != nullptr) {
                          // Use identifiers unique to the stores in current BB
                          curLocID =
                              ConstantInt::get(Int8Ty, (uint8_t)BB_store_count);
                        } else {
                          // Use globally unique identifiers
                          curLocID =
                              ConstantInt::get(Int32Ty, RandBelow(map_size));
                        }  // if not ONE_INSTRUMENTATION_PER_BB

                        BB_store_count++;

                        storeLocationToID.insert(
                            std::pair<Value *, ConstantInt *>(
                                storeLocationPhi->getIncomingValue(i), curLocID));
                      } else {
                        curLocID = curLocIDIter->getSecond();
                      }

                      CurLocPhi->addIncoming(
                          curLocID, storeLocationPhi->getIncomingBlock(i));
                    }
                    CurLoc = CurLocPhi;

                  } else {  // if store location is not a PHI
                    if (getenv("ONE_INSTRUMENTATION_PER_BB") != nullptr) {
                      // Use an identifier unique to the stores in the current BB
                      CurLoc = ConstantInt::get(Int32Ty, BB_store_count);
                    } else {
                      /* Make up globally unique location_id */
                      cur_loc = RandBelow(map_size);
                      CurLoc = ConstantInt::get(Int32Ty, cur_loc);
                    }  // if not ONE_INSTRUMENTATION_PER_BB
                    BB_store_count++;
                  }  // if store location is not a PHI

                  bitmask_selector = RandBelow(8);

                  // Get a valid insert point (ideally directly after the value definition
                  if ((isa<PHINode>(storeLocation)) ||
                      !getInsertionPointInSameBB(valueDefInstruction,
                                                 insertionPoint)) {
                    if (!(isa<PHINode>(storeLocation))) {
                      errs()
                          << "WARNING: Could not find insertion point in BB of "
                             "value definition function '"
                          << F.getName() << "'val: " << storedValue << "\n";
                      if (Debug) {
                        dbgs() << valueDefInstruction->getParent() << "\n";
                      }
                    }

                    if (!getInsertionPointInSameBB(storeInst, insertionPoint)) {
                      // We failed to find an insertion point both close to
                      // definition and store, what now???
                      errs()
                          << "ERROR: Could not find insertion point in function "
                             "'"
                          << F.getName() << "' val: " << storedValue << "\n";
                      if (Debug) { dbgs() << storeInst->getParent() << "\n"; }
                      assert(0);
                    }
                  }
                  BasicBlock *insertionBB = (*insertionPoint).getParent();
                  IRB.SetInsertPoint(insertionBB, insertionPoint);

                  // TODO: Check for pointer (is this necessary?)
                  Value *StoredValue64Bit =
                      IRB.CreateZExtOrTrunc(storedValue, IRB.getInt64Ty());

                  if (getenv("ONE_INSTRUMENTATION_PER_BB") == nullptr) {
                    if (getenv("STORFUZZ_INSTR_STYLE_FUNC")) {
                      Value       *args[] = {CurLoc, Mask[bitmask_selector],
                                             StoredValue64Bit};
                      Instruction *call = IRB.CreateCall(coverageFunc, args);
                      call->setMetadata(M.getMDKindID("nosanitize"),
                                        MDNode::get(C, None));
                    } else {
                      // Inline instrumentation at every store without function calls
                      Value *cmp =
                          IRB.CreateCmp(CmpInst::ICMP_SLT, StoredValue64Bit,
                                        ConstantInt::get(Int64Ty, 0x400000));
                      Value *mask = IRB.CreateSelect(cmp, Mask[bitmask_selector],
                                                     ConstantInt::get(Int8Ty, 0));

                      Value *Lower16Bit =
                          IRB.CreateZExtOrTrunc(storedValue, IRB.getInt16Ty());
                      dyn_cast<Instruction>(Lower16Bit)
                          ->setMetadata(M.getMDKindID("storfuzz_get_val"),
                                        MDNode::get(C, None));
                      Value *Upper8Bit = IRB.CreateZExtOrTrunc(
                          IRB.CreateLShr(Lower16Bit, 8), IRB.getInt8Ty());
                      Value *Lower8Bit =
                          IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());

                      Value *ReducedValue;
                      ReducedValue = IRB.CreateXor(Upper8Bit, Lower8Bit);

                      // Get Map location
                      LoadInst *MapPtrLoad = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
                          PointerType::get(Int8Ty, 0),
#endif
                          StorFuzzMapPtr);
                      MapPtrLoad->setMetadata(M.getMDKindID("nosanitize"),
                                              MDNode::get(C, None));

                      // Calculate Index in map
                      Value *MapPtrIdx;
                      MapPtrIdx = IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
                          Int8Ty,
#endif
                          MapPtrLoad,
                          IRB.CreateXor(CurLoc,
                                        IRB.CreateZExtOrTrunc(ReducedValue,
                                                              IRB.getInt32Ty())));
                      dyn_cast<Instruction>(MapPtrIdx)->setMetadata(
                          M.getMDKindID("storfuzz_calc_index"),
                          MDNode::get(C, None));
                      if (getenv("STORFUZZ_VERBOSE")) {
                        errs() << "MapPtrIdx: " << MapPtrIdx
                               << "\ninsertion BB: " << insertionBB << "\n";
                      }
// Write to map (threadsafe by default)
#if 1
                      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Or,
                                          MapPtrIdx, mask,
#if LLVM_VERSION_MAJOR >= 13
                                          llvm::MaybeAlign(1),
#endif
                                          llvm::AtomicOrdering::Monotonic);
#else  // Not threadsafe
                      LoadInst *BitMapEntry = IRB.CreateLoad(
  #if LLVM_VERSION_MAJOR >= 14
                        IRB.getInt8Ty(),
  #endif
                        MapPtrIdx);
                    BitMapEntry->setMetadata(M.getMDKindID("nosanitize"),
                                             MDNode::get(C, None));

                    Value *UpdatedEntry = IRB.CreateOr(BitMapEntry, mask);

                    IRB.CreateStore(UpdatedEntry, MapPtrIdx)
                        ->setMetadata(M.getMDKindID("nosanitize"),
                                      MDNode::get(C, None));

#endif                    // Not threadsafe
                    }       // Inline instrumentation without functions
                  } else {  // ONE_INSTRUMENTATION_PER_BB
                    if(only_one_store){
                      // If there is only one store in the block, we can use an optimized function:
                      //__storfuzz_store_single_aggregated_value(uint16_t bb_id, uint8_t bitmask, uint64_t value)
                      Value *args[] = {BB_id, Mask[BB_bitmask_selector], StoredValue64Bit};
                      Instruction *call_to_aggregate =
                          IRB.CreateCall(store_single_aggregated_Func, args);
                      call_to_aggregate->setMetadata(
                          M.getMDKindID("nosanitize"), MDNode::get(C, None));

                    } else {
                      // Add each stored value to aggregated value

                      // Give each store in BB a unique ID to avoid that same values stored cancel each other out The ZExtOrTrunc should always be eliminated by optimization
                      Value *StoreID = IRB.CreateZExtOrTrunc(CurLoc, Int8Ty);

                      Value       *args[] = {StoreID, StoredValue64Bit};
                      Instruction *call_to_aggregate =
                          IRB.CreateCall(aggregate_func, args);
                      call_to_aggregate->setMetadata(
                          M.getMDKindID("nosanitize"), MDNode::get(C, None));

                      if (BB_store_count >= 256) {
                        errs()
                            << "WARNING: More than 256 instrumented stores in a BB, now we have collisions in the loc_id! "
                            << M.getName() << ": " << F.getName() << ": "
                            << BB.getName() << "\n";
                      } // if BB_store_count >= 256
                    }   // !only_one_store
                  }     // ONE_INSTRUMENTATION_PER_BB
                }       // If instrument_this_time
              }         // If stored value is an integer
            }           // If storeLocation is no alloc
          }             // if instr is store
        }               // Iter instructions in BB

        // Bail out if there are no stores to instrument in the current basic block
        if(BB_store_count == 0){
          break;
        }
        // Bail out if there are too many stores to instrument
        if (BB_store_count > THRESHOLD){
          dbgs() << "DEBUG: Not instrumenting '" << M.getName() << ": " << F.getName() << ": " << BB.getName() <<
              "' because it has more than " << itostr(THRESHOLD) << " stores\n";
          break;
        }

      } while (!instrument_this_time);

      if(instrument_this_time && getenv("ONE_INSTRUMENTATION_PER_BB") && !only_one_store) {
        // Store aggregated value to map
        if (BB_store_count > 0) {
          Value       *args[] = {BB_id, Mask[BB_bitmask_selector]};
          Instruction *call_to_store_aggregated =
              IRB.CreateCall(store_aggregated_Func, args);
          call_to_store_aggregated->setMetadata(M.getMDKindID("nosanitize"),
                                                MDNode::get(C, None));
        }  // if at least one store was done in BB
      } // instrument_this_time && ONE_INSTRUMENTATION_PER_BB && !only_one_store

      // Don't skew statistics if we didn't instrument anything
      if(!instrument_this_time){
        BB_store_count = 0;
      }

      auto I = BB.getFirstNonPHIOrDbg(true);
      auto line_num = I->getDebugLoc() ? std::to_string(I->getDebugLoc().getLine()) : "?";

      std::string msg = M.getName().str() + ":" + F.getName().str() + ":" + BB.getName().str()
                        + " line: " + line_num
                        + " | " + std::to_string(BB_store_count);

      log("STORES_PER_BB", msg);

      inst_stores += BB_store_count;
    } // Iter BBs in Func
  } // Iter Funcs in Module

  outs() << "StorFuzz on '" << M.getName() << "': Instrumented " <<  inst_stores << " targets\n";

  if (getenv("STORFUZZ_DUMP_CONVERTED")) {
    raw_ostream &out = outs();
    M.print(out, nullptr);
  }
#ifdef USE_NEW_PM
  return PA;
#else
  return true;
#endif
}

#ifndef USE_NEW_PM
static void registerStorFuzzPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
  PM.add(new StorFuzzCoverage());
}

static RegisterStandardPasses RegisterStorFuzzPass(
    PassManagerBuilder::EP_OptimizerLast, registerStorFuzzPass);

static RegisterStandardPasses RegisterStorFuzzPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerStorFuzzPass);
#endif
