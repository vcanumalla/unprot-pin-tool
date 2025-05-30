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
UINT64 staticUnprotCount = 0; // number of unprotected instructions
UINT64 dynamicUnprotCount = 0;

// reg mapping to whether it is unprotected during instrumentation (True if unprotected)
std::map<std::string, bool> regUnprotMap;
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

    // ss op y z
    UINT8 is_ss;
    PIN_SafeCopy(&is_ss, (void*)INS_Address(ins), sizeof(UINT8));
    if (is_ss == 0x36) {
        // 3 cases: ss move rd rs, ss mov rd [ptr] ss op rd [ptr]

        // ss mov rd rs and ss mov rd [ptr] --> g[rd] <== 1
        if (op == "MOV" && INS_OperandCount(ins) == 2 && INS_OperandIsReg(ins, 0)) {
            REG reg = INS_OperandReg(ins, 0);
            std::string regName = REG_StringShort(reg);
            if (!INS_OperandIsReg(ins, 1)) {
                cerr << "Second operand is not a register: " << INS_Disassemble(ins) << endl;
            }
            regUnprotMap[regName] = true; // mark as unprotected
        }

        // ss op rd [ptr] --> g[rd] <== g[rd]
        // no work since result stays the same as previous value
    }
    else {
        if (op == "ADD" || op == "SUB" || op == "MUL" || op == "DIV" ||
            op == "AND" || op == "OR" || op == "XOR") {
            // op rd rs --> g[rd] <== g[rd] + g[rs]
            if (INS_OperandCount(ins) == 2 && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
                // collect the operand names
                bool val1 = regUnprotMap.find(REG_StringShort(INS_OperandReg(ins, 0))) != regUnprotMap.end() &&
                            regUnprotMap[REG_StringShort(INS_OperandReg(ins, 0))];
                bool val2 = regUnprotMap.find(REG_StringShort(INS_OperandReg(ins, 1))) != regUnprotMap.end() &&
                            regUnprotMap[REG_StringShort(INS_OperandReg(ins, 1))];
                regUnprotMap[REG_StringShort(INS_OperandReg(ins, 0))] = val1 && val2; // mark as protected if either operand is protected.
            }
        }
        // mov rd [ptr] -> g[rd] <== 0
        else if (op == "MOV" && INS_OperandCount(ins) == 2 && INS_OperandIsReg(ins, 0) && !INS_OperandIsReg(ins, 1)) {
            REG reg = INS_OperandReg(ins, 0);
            std::string regName = REG_StringShort(reg);
            regUnprotMap[regName] = false; // mark as protected
        }
    }

    // sub/add/mul... rd [ptr]

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
