/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <map>
using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 insCount    = 0; //number of dynamically executed instructions
UINT64 bblCount    = 0; //number of dynamically executed basic blocks
UINT64 threadCount = 0; //total number of threads, including main thread
UINT64 totalReprotects;
UINT64 totalUnprotects;
bool CONST_TRUE = true;
bool CONST_FALSE = false;
// reg mapping to whether it is unprotected during instrumentation (True if unprotected)
std::map<std::string, bool> regUnprotMap;
std::map<ADDRINT, UINT64> insReprotectCount;
std::map<ADDRINT, std::string> insReprotectDisasm;
std::ostream* out = &cerr;
/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
                       "count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl
         << "instructions, basic blocks and threads in the application." << endl
         << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

VOID incCount(UINT64* val)
{
    (*val)++;
}

VOID tryChangeRegSS(UINT64* addr_count, bool* dest_prot, bool* src1) {
    *addr_count += !(*src1);
    *dest_prot = true;
}
// preprocess: compute dest_prot, src1, src2, is_ss
//  src1 && src2, if  dest_prot goes to false from true increment addr_count
// update dest_prot if necessary
// (UINT64* addr_count, bool* dest_prot, bool* src1, bool* src2, bool is_ss)
VOID tryChangeRegStatus(UINT64* addr_count, bool* dest_prot, bool* src1, bool* src2, bool is_ss) {
    // other ss wont route to here
    if (is_ss) {
        *dest_prot = true;

    }
    else {
        // cerr << "in call\n";
        // not ss
        bool og = *dest_prot;
        *dest_prot = *src1 && *src2;
        // go from unprotected to protected
        (*addr_count) += (og && !*dest_prot);
        totalReprotects += (og && !*dest_prot);
    }
}




/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID* v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID Instruction(INS ins, VOID* v) {
    std::string op = INS_Mnemonic(ins);
    // cerr << "Instrumenting..." << INS_Disassemble(ins) << " at " << std::hex << INS_Address(ins) << std::dec << endl;
    int opCount = INS_OperandCount(ins);
    for (int i = 0; i < opCount; i++) {
        if (INS_OperandIsReg(ins, i)) {
            REG reg = INS_OperandReg(ins, i);
            std::string regName = REG_StringShort(reg);
            
            // add reg to the map if not present
            if (regUnprotMap.find(regName) == regUnprotMap.end()) {
                bool val = false;
                regUnprotMap[regName] = val;// mark as protected
            }
        }
    }
    // analysis
    UINT8 is_ss;
    PIN_SafeCopy(&is_ss, (void*)INS_Address(ins), sizeof(UINT8));

    // ss mov rd rs and ss mov rd [ptr] --> g[rd] <== 1
    if (is_ss == 0x36) {
        // cerr << "SS instruction:\n"; 
        if (op == "MOV" && INS_OperandCount(ins) >= 2 && INS_OperandIsReg(ins, 0)) {

                // this is a possibly interesting change, mark this address.
                REG reg = INS_OperandReg(ins, 0);
                std::string regName = REG_StringShort(reg);

                // make sure the register is in the map and addr_count is initialized
                if (regUnprotMap.find(regName) == regUnprotMap.end()) {

                    bool val = false;
                    regUnprotMap[regName] = val; // mark as protected
                }
                if (insReprotectCount.find(INS_Address(ins)) == insReprotectCount.end()) {
                    insReprotectCount[INS_Address(ins)] = 0;
                    insReprotectDisasm[INS_Address(ins)] = INS_Disassemble(ins);
                }
                // cerr << "about to insert call\n";
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tryChangeRegStatus,
                    IARG_PTR, &insReprotectCount[INS_Address(ins)],
                    IARG_PTR, &regUnprotMap[regName],
                    IARG_PTR, &CONST_TRUE, // not used, doesnt matter
                    IARG_PTR, &CONST_TRUE, // not used, doesnt matter
                    IARG_BOOL, true, // ss
                    IARG_END // end of args
                );
        }
    }
    else {
        // cerr << "Non-SS instruction:\n";
        // non ss instructions.
        // op rd rs1 ... rsN: could be memory or register operands or constants
        if (INS_OperandCount(ins) > 0 && INS_OperandIsReg(ins, 0) && INS_OperandWritten(ins, 0)) {
            // cerr << "actually going to do logic for instruction: " << INS_Disassemble(ins) << " at " << std::hex << INS_Address(ins) << std::dec << endl;
            // error checking
            if (regUnprotMap.find(REG_StringShort(INS_OperandReg(ins, 0))) == regUnprotMap.end()) {
                bool val = false;
                regUnprotMap[REG_StringShort(INS_OperandReg(ins, 0))] = val; // mark as protected
            }
            if (insReprotectCount.find(INS_Address(ins)) == insReprotectCount.end()) {
                insReprotectCount[INS_Address(ins)] = 0;
                insReprotectDisasm[INS_Address(ins)] = INS_Disassemble(ins);
            }
            // cerr << "got past error checking:\n";
            bool* dest_prot = &regUnprotMap[REG_StringShort(INS_OperandReg(ins, 0))];
            // one operand
            bool* src1 = &CONST_TRUE;
            bool* src2 = &CONST_TRUE;
            if (INS_OperandCount(ins) >= 2) {
                if (INS_OperandIsMemory(ins, 1)) {
                    src1 = &CONST_FALSE; // memory is always protected
                }
                // reg that we need to make sure is in the map for future
                else if (INS_OperandIsReg(ins, 1)) {
                    REG reg = INS_OperandReg(ins, 1);
                    std::string regName = REG_StringShort(reg);
                    if (regUnprotMap.find(regName) != regUnprotMap.end()) {
                        src1 = &regUnprotMap[regName];
                    }
                    // not in map, add it
                    else {
                        regUnprotMap[regName] = false;
                        src1 = &regUnprotMap[regName];
                    }
                }
                // constant that is always unprot (leaked through opcode)
                else {
                    src1 = &CONST_TRUE;
                }
                // cerr << "finished 2\n";
            }
            else if (INS_OperandCount(ins) == 3) {
                if (INS_OperandIsMemory(ins, 2)) {
                    src2 = &CONST_FALSE;
                }
                else if (INS_OperandIsReg(ins, 2)) {
                    REG reg = INS_OperandReg(ins, 2);
                    std::string regName = REG_StringShort(reg);
                    if (regUnprotMap.find(regName) != regUnprotMap.end()) {
                        src2 = &regUnprotMap[regName];
                    }
                    // not in map, add it
                    else {
                        regUnprotMap[regName] = false;
                        src2 = &regUnprotMap[regName];
                    }
                }
                else {
                    src2 = &CONST_TRUE;
                }
            }
            else if (INS_OperandCount(ins) == 1) {
                // no src2, just use CONST_TRUE
            }
            else {
                cerr << "Unhandled instruction with more than 3 operands: " << INS_Disassemble(ins) << " at " << std::hex << INS_Address(ins) << std::dec << endl;
                cerr << "Info: " << INS_OperandCount(ins) << std::endl;
            }
            // cerr << "about to insert call for instruction: " << INS_Disassemble(ins) << " at " << std::hex << INS_Address(ins) << std::dec << endl;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tryChangeRegStatus,
                IARG_PTR, &insReprotectCount[INS_Address(ins)],
                IARG_PTR, dest_prot,
                IARG_PTR, src1,
                IARG_PTR, src2,
                IARG_BOOL, false, IARG_END // not ss
            );
        }
        // not a write, can pass
    }
}
    
 

VOID ThreadStart(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v) { threadCount++; }

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v)
{
    *out << "===============================================" << endl;
    *out << "MyPinTool analysis results: " << endl;
    *out << "===============================================" << endl;
    
    *out << "Total number of executed instructions: " << insCount << endl;
    *out << "Total number of executed basic blocks: " << bblCount << endl;
    *out << "Total number of threads: " << threadCount << endl;

    *out << "Total number of register unprotections: " << totalUnprotects << endl;
    *out << "Total number of register reprotections: " << totalReprotects << endl;
    *out << "Total number of unique registers unprotected: " << regUnprotMap.size() << endl;
    *out << "===============================================" << endl;
    *out << "===============================================" << endl;

    *out << "Reprotections per instruction for csv:" << endl;
    *out << "Instruction Address,Reprotect Count, Instruction" << endl;
    for (const auto& entry : insReprotectCount) {
        ADDRINT addr = entry.first;
        UINT64 count = entry.second;
        std::string disasm = insReprotectDisasm[addr];
        *out << std::hex << addr << "," << count << "," << std::dec << disasm << std::dec << endl;
    }
    


}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    string fileName = KnobOutputFile.Value();
    if (!fileName.empty())
    {
        out = new std::ofstream(fileName.c_str());
    }

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);
        // Register function to be called to instrument instructions
        INS_AddInstrumentFunction(Instruction, 0);
        // Register function to be called for every thread before it starts running
        PIN_AddThreadStartFunction(ThreadStart, 0);
        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr << "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
