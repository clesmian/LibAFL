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
};

}  // namespace

#ifdef USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
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
          }};
}
#else

char StorFuzzCoverage::ID = 0;
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
  auto PA = PreservedAnalyses::all();
#endif

  /* Setup random() so we get Actually Random(TM) */
  rand_seed = time(NULL);
  srand(rand_seed);

  GlobalVariable *StorFuzzMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__storfuzz_area_ptr");


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

    // if (!isInInstrumentList(&F)) { continue; }

    if (F.size() < function_minimum_size) { continue; }

    std::list<Value *> todo;
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
          AllocaInst *allocaInst;
          if (!(dyn_cast<AllocaInst>(storeLocation))) {
            Value       *storedValue = storeInst->getValueOperand();

            // If the stored value does not stem from an instruction it is not
            // interesting
            Instruction* storedValueInstruction;
            if (!(storedValueInstruction = dyn_cast<Instruction>(storedValue)))
              continue;

            IntegerType *storedType =
                dyn_cast<IntegerType>(storedValue->getType());
            if (storedType) {
              // Insert before the instruction following the value definition
              IRB.SetInsertPoint(
                  storedValueInstruction->getNextNode());
              Value *ReducedValue;

              // TODO: Check for pointer (is this necessary?)

              // Reduce Value to 8 bit
              ReducedValue = IRB.CreateXorReduce(IRB.CreateBitCast(
                  IRB.CreateZExtOrTrunc(storedValue, IRB.getInt16Ty()),
                  VectorType::get(IRB.getInt8Ty(), 2, false)));

              /* Make up location_id */
              cur_loc = RandBelow(map_size);
              ConstantInt *CurLoc;
              CurLoc = ConstantInt::get(Int32Ty, cur_loc);

              auto bitmask_selector = RandBelow(8);

              // Get Map location
              LoadInst *MapPtr = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
                  PointerType::get(Int8Ty, 0),
#endif
                  StorFuzzMapPtr);
              MapPtr->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

              // Calculate Index in map
              Value *MapPtrIdx;
              MapPtrIdx = IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
                  Int8Ty,
#endif
                  MapPtr, IRB.CreateXor(ReducedValue, CurLoc));

              // Write to map (threadsafe by default)
              IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Or, MapPtrIdx,
                                  Mask[bitmask_selector],
#if LLVM_VERSION_MAJOR >= 13
                                  llvm::MaybeAlign(1),
#endif
                                  llvm::AtomicOrdering::Monotonic);

              inst_stores++;
            }
          }
        }
      }
    }
  }

  if (Debug) {
    if (!inst_stores)
      fprintf(stderr, "No instrumentation targets found.\n");
    else
      fprintf(stderr, "Instrumented %d targets.\n", inst_stores);
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
