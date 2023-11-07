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
#include "llvm/ADT/DenseMap.h"
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
static cl::opt<bool>     Debug("debug_storfuzz_coverage", cl::desc("Debug prints"),
                               cl::init(false), cl::NotHidden);


namespace {

#ifdef USE_NEW_PM
class StorFuzzCoverage : public PassInfoMixin<StorFuzzCoverage> {
 public:
  StorFuzzCoverage() {
#else
class StorFuzzCoverage : public ModulePass {
 public:
  static char ID;
  StorFuzzCoverage() : ModulePass(ID) {
#endif
  }

#ifdef USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  uint32_t                          map_size = DATA_MAP_SIZE;
  uint32_t                          function_minimum_size = 1;

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
  LLVMContext &C = M.getContext();


  Type *VoidTy = Type::getVoidTy(C);

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  Type *Int8PtrTy = PointerType::getUnqual(IntegerType::getInt8Ty(C));
  Type *Int16PtrTy = PointerType::getUnqual(IntegerType::getInt16Ty(C));
  Type *Int32PtrTy = PointerType::getUnqual(IntegerType::getInt32Ty(C));
  Type *Int64PtrTy = PointerType::getUnqual(IntegerType::getInt64Ty(C));
  Type *Int128PtrTy = PointerType::getUnqual(IntegerType::getInt128Ty(C));

  uint32_t     rand_seed;
  unsigned int cur_loc = 0;

#ifdef USE_NEW_PM
  auto PA = PreservedAnalyses::none();
#endif

  /* Setup random() so we get Actually Random(TM) */
  rand_seed = time(NULL);
  srand(rand_seed);

  GlobalVariable *StorFuzzMapPtr =
      new GlobalVariable(M, PointerType::getUnqual(Int8Ty), false,
                         GlobalValue::ExternalWeakLinkage, nullptr, "__storfuzz_area_ptr");


  // other constants we need
  ConstantInt * Mask[8] = {
      ConstantInt::get(Int8Ty, 1 << 0),
      ConstantInt::get(Int8Ty, 1 << 1),
      ConstantInt::get(Int8Ty, 1 << 2),
      ConstantInt::get(Int8Ty, 1 << 3),
      ConstantInt::get(Int8Ty, 1 << 4),
      ConstantInt::get(Int8Ty, 1 << 5),
      ConstantInt::get(Int8Ty, 1 << 6),
      ConstantInt::get(Int8Ty, 1 << 7)
  };

  /* Instrument all the things! */

  int inst_stores = 0;
  // scanForDangerousFunctions(&M);

  for (auto &F : M) {
    int has_calls = 0;
    if (Debug)
      fprintf(stderr, "FUNCTION: %s (%zu)\n", F.getName().str().c_str(),
              F.size());
    if (isIgnoreFunction(&F)){
      if (Debug)
        fprintf(stderr, "Ignoring function %s\n", F.getName().str().c_str());
      continue;
    }

    if (F.size() < function_minimum_size) { continue; }


    for (auto &BB : F) {
      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));
      for (auto &instr : BB) {
        StoreInst *storeInst;
        if ((storeInst = dyn_cast<StoreInst>(&instr))) {
          // Check that this instruction is not already part of AFL instrumentation
          if(storeInst->getMetadata("nosanitize") != nullptr)
            continue;

          Value      *storeLocation = storeInst->getPointerOperand();
          if (!(dyn_cast<AllocaInst>(storeLocation))) {
            Value       *storedValue = storeInst->getValueOperand();

            // If the stored value does not stem from an instruction it is not
            // interesting
            Instruction* storedValueInstruction;
            if (!(storedValueInstruction = dyn_cast<Instruction>(storedValue)))
              // TODO: Check for interesting operations (e.g. not simply a load and store, but some change)
              continue;

            IntegerType *storedType =
                dyn_cast<IntegerType>(storedValue->getType());
            if (storedType) {
              // Insert before the instruction following the value definition
              if (getenv("STORFUZZ_VERBOSE")) {
                BB.dump();
                fprintf(stderr, "Stored value: ");
                storedValue->dump();
                fprintf(stderr, "Store instruction: ");
                storeInst->dump();
              }

              IP = storedValueInstruction->getNextNode()->getIterator();
              BasicBlock::const_iterator End = BB.end();
              int i = 0;
              while(IP != End && i < BB.size()){
                if (isa<PHINode>(IP)){
                  IP++;
                } else if (IP->isEHPad()) {
                  IP++;
                } else if (BB.isEntryBlock()) {
                    while (IP != End && i < BB.size() &&
                           (isa<AllocaInst>(*IP) || isa<DbgInfoIntrinsic>(*IP) ||
                            isa<PseudoProbeInst>(*IP))) {
                      if (const AllocaInst *AI = dyn_cast<AllocaInst>(&*IP)) {
                        if (!AI->isStaticAlloca())
                          break;
                      }
                      ++IP;
                      i++;
                    }
                    break;
                } else {
                    break;
                }
                i++;
              }
              if(IP == End || i == BB.size()){

                  fprintf(stderr, "ERROR: Could not find insertion point in function '%s' val: ", F.getName().str().c_str());
                  storedValue->dump();
                  BB.dump();
              }
              IRB.SetInsertPoint(&BB, IP);

              // TODO: Check for pointer (is this necessary?)

              Value *Lower16Bit = IRB.CreateZExtOrTrunc(storedValue, IRB.getInt16Ty());
              dyn_cast<Instruction>(Lower16Bit)->setMetadata(M.getMDKindID("storfuzz_get_val"),
                                      MDNode::get(C, None));
//              // TODO: Reduce Value to 8 bit
              Value* Upper8Bit = IRB.CreateZExtOrTrunc(IRB.CreateLShr(Lower16Bit, 8), IRB.getInt8Ty());
              Value* Lower8Bit = IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());

              Value *ReducedValue;
//              ReducedValue = IRB.CreateXor(
//                  IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty()),
//                  IRB.CreateZExtOrTrunc(, IRB.getInt8Ty()));
//              ReducedValue = IRB.CreateXor(Upper8Bit, Lower8Bit);
              ReducedValue = IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());

              dyn_cast<Instruction>(ReducedValue)->setMetadata(M.getMDKindID("storfuzz_reduced"),
                                        MDNode::get(C, None));
              ReducedValue = IRB.CreateXor(Upper8Bit, Lower8Bit);

              /* Make up location_id */
              cur_loc = RandBelow(map_size);
              ConstantInt *CurLoc;
              CurLoc = ConstantInt::get(Int32Ty, cur_loc);

              auto bitmask_selector = RandBelow(7);

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
                  IRB.CreateXor(
                      CurLoc,
                      IRB.CreateZExtOrTrunc(ReducedValue, IRB.getInt32Ty())
                      )
                  );
              dyn_cast<Instruction>(MapPtrIdx)->setMetadata(M.getMDKindID("storfuzz_calc_index"),
                                     MDNode::get(C, None));
              if (getenv("STORFUZZ_VERBOSE")) {
                fprintf(stderr, "MapPtrIdx: ");
                MapPtrIdx->dump();
                BB.dump();
              }
                // Write to map (threadsafe by default)
#if 1 // Threadsafe (this somehow crashes)
              IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Or, MapPtrIdx,
                                  Mask[bitmask_selector],
#if LLVM_VERSION_MAJOR >= 13
                                  llvm::MaybeAlign(1),
#endif
                                  llvm::AtomicOrdering::Monotonic);
#else // Not threadsafe (not clear whether this also crashes)
         LoadInst *BitMapEntry = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          IRB.getInt8Ty(),
#endif
          MapPtrIdx);
         BitMapEntry->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

Value *UpdatedEntry = IRB.CreateOr(BitMapEntry, Mask[bitmask_selector]);

IRB.CreateStore(UpdatedEntry, MapPtrIdx)
   ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

#endif
              inst_stores++;
            }
          }
        }
      }
//      for (auto &I : BB) {
//        if (!I.isTerminator()){
//          Value *V = &I;
////          I.dump();
////          V->getType()->isEmptyTy();
//
//        }
//      }
    }


  }

  if (Debug) {
    if (!inst_stores)
      fprintf(stderr, "No instrumentation targets found.\n");
    else
      fprintf(stderr, "Instrumented %d targets.\n", inst_stores);
  }

  if(getenv("STORFUZZ_DUMP_CONVERTED")){
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
