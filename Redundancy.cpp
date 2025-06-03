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
// reg mapping to whether it is unprotected during instrumentation (True if unprotected)
std::map<std::string, bool*> regUnprotMap;
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
/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Helper to count reprotections. Add to map if not present, and increment reprotects if it is being changed from unprotected to protected.
// Increment total unprotects whenever a register is changed to unprotected (even if redundant).
VOID changeRegStatus(std::string regName, bool unprotect, INS ins) {
    // changing to unprotected
    if (unprotect) {
        
        totalUnprotects++;
        // reg in map and unprotected already, do nothing.
        if (regUnprotMap.find(regName) != regUnprotMap.end() && regUnprotMap[regName]) {
        }
        // reg not in map (protected), or protected in map, so we change its value in map to true
        else {
            // if it is not in the map, it means it is protected

            regUnprotMap[regName] = 
        }
    }
    else {
        // changing to protected
        // reg in map and unprotected, so we change its value in map to false
        if (regUnprotMap.find(regName) != regUnprotMap.end() && regUnprotMap[regName]) {
            regUnprotMap[regName] = false;

            totalReprotects++;
            ADDRINT insAddr = INS_Address(ins);
            if (insReprotectCount.find(insAddr) == insReprotectCount.end()) {
                insReprotectCount[insAddr] = 1;
                insReprotectDisasm[insAddr] = INS_Disassemble(ins); // store disassembly for this instruction
            }
            else {
                insReprotectCount[insAddr]++; // increment reprotection count for this register
            }
        }
        // reg not in map (protected), add to map and mark as protected
        else if (regUnprotMap.find(regName) == regUnprotMap.end()) {
            regUnprotMap[regName] = false; // mark as protected
        }
        // else, reg is in map and protected, do nothing
    }

}
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
            changeRegStatus(regName, true, ins); // mark as unprotected
            // regUnprotMap[regName] = true; // mark as unprotected
        }

        // ss op rd [ptr] --> g[rd] <== g[rd]
        // no work since result stays the same as previous value
        else if (INS_OperandCount(ins) == 2 && INS_OperandIsReg(ins, 0) && !INS_OperandIsReg(ins, 1)) {
            REG reg = INS_OperandReg(ins, 0);
            std::string regName = REG_StringShort(reg);
            if (regUnprotMap.find(regName) == regUnprotMap.end()) {
                // if the register is not in the map, it means it is protected.
                // so we add it to the map and mark it as protected.
                changeRegStatus(regName, false, ins);
            }
            // in map and has value, do nothing.
        }
        else {
            cerr << "Unhandled ss instruction: " << INS_Disassemble(ins) << "at " << std::hex << INS_Address(ins) << std::dec << endl;
        }
    }
    else {
        // if there is an output reg being written to, we check to see what its new value is
        // op rd rs1 ... rsN
        if (INS_OperandCount(ins) > 0 && INS_OperandIsReg(ins, 0) && INS_OperandWritten(ins, 0)) {
            // cerr << "Instruction writing to register: " << INS_Disassemble(ins) << " at " << std::hex << INS_Address(ins) << std::dec << endl;

            bool val = true;
            if (INS_OperandCount(ins) == 1) {
                val = false;
                // err if its not pop or not
                // if (op != "POP" && op != "NOT") {
                //     cerr << "Instruction writing to register with no other operands: " << INS_Disassemble(ins) << " at " << std::hex << INS_Address(ins) << std::dec << endl;
                // }
            }
            else {
                for (UINT32 i = 0; i < INS_OperandCount(ins); i++) {
                    if (INS_OperandIsReg(ins, i)) {
                        REG reg = INS_OperandReg(ins, i);
                        std::string regName = REG_StringShort(reg);
                        if (regUnprotMap.find(regName) != regUnprotMap.end()) {
                            val &= regUnprotMap[regName];
                        }
                        else {
                            // its protected if it is not in the map
                            val = false;
                            break;
                        }
                    }
                    else if (INS_OperandIsMemory(ins, i)) {
                        // if the operand is memory, we assume it is protected
                        val = false;
                        break;
                    }
                }
            }
            REG reg = INS_OperandReg(ins, 0);
            std::string regName = REG_StringShort(reg);
            
            // regUnprotMap[regName] = val;
            changeRegStatus(regName, val, ins); // mark as unprotected if val is true, protected if false
        }
        // sub/add/mul... rd [ptr]: g[rd] <== 0
        else if (INS_OperandCount(ins) == 2 && INS_OperandIsReg(ins, 0) && !INS_OperandIsReg(ins, 1)) {
            REG reg = INS_OperandReg(ins, 0);
            std::string regName = REG_StringShort(reg);
            changeRegStatus(regName, false, ins);
        }
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
