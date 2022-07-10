/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//
// Search for know Commodore 64 Kernal and ROM calls and add a comment with the description of 
// the call itself.
// 
// Sources used to map the calls:
// https://sta.c64.org/cbm64krnfunc.html
// https://www.c64-wiki.com/wiki/BASIC-ROM
//
// @category Analysis
// @author Cesare Pizzi

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;

public class FindC64KernalROMCalls extends GhidraScript {
    
    private int debug = 0;
    Map<String, String> callsMap = new HashMap<String, String>();

    @Override
    public void run() throws Exception {

        println("*** - FindC64KernalROMCalls - Starting...");
        
        Address addr = currentProgram.getMemory().getMinAddress();
        PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);

        AddressSetView execSet = currentProgram.getMemory().getExecuteSet();
        AddressSet disSet = new AddressSet();

        // Load mapping
        loadKernalROMCallMap();

        while (addr != null) {
            addr = this.find(addr, (byte) 0x20);
            if (addr == null) {
                break;
            }
            Instruction instr = currentProgram.getListing().getInstructionAt(addr);
            if (debug >= 2 ) {
                println("DEBUG-> Address: " + addr + " Instruction: " + instr);
            }
            
            // If null, go ahead with next address
            if (instr == null ) {
                addr = addr.add(1);
                continue;
            }
            
            boolean iscall = instr.getFlowType().isCall();
            
            if (debug >= 1 ) {
                println("DEBUG-> IsCall: " + iscall);
            }
            
            // Get the called address
            Address target = instr.getAddress(0);
            if (debug >= 1 ) {
                println("DEBUG-> Called address: " + target);
            }

            // Map the call with known addresses
            String callDesc = callsMap.get(target.toString());
       
            // If the returned value is not null, set the comment 
            if (callDesc != null) {
                String comment = instr.getComment(Instruction.EOL_COMMENT);
                if (comment == null) {
                    instr.setComment(Instruction.EOL_COMMENT, callDesc);
                    
                    if (debug >= 1) {
                        println("DEBUG-> Comment set at address " + addr );
                    }
                } else {
                    println("JSR at adddress " + addr + " already have a comment, not adding (" + callDesc + ")");
                }
                            
                // Add the call to the listing
                disSet.add(addr);
            }

            addr = addr.add(1);
        }

        show("C64 Kernal Calls", disSet);
        println("*** - FindC64KernalROMCalls - End");
    }
    
    private void loadKernalROMCallMap() {

        //
        // Comodore 64 Kernal
        //
        callsMap.put("ff81","SCINIT: Initialize VIC; restore default input/output to keyboard/screen; clear screen; set PAL/NTSC switch and interrupt timer");
        callsMap.put("ff84","IOINIT: Initialize CIA's, SID volume; setup memory configuration; set and start interrupt timer");        
        callsMap.put("ff87","RAMTAS: Clear memory addresses $0002-$0101 and $0200-$03FF; run memory test and set start and end address of BASIC work area accordingly; set screen memory to $0400 and datasette buffer to $033C");
        callsMap.put("ff8a","RESTOR: Fill vector table at memory addresses $0314-$0333 with default values");
        callsMap.put("ff8d","VECTOR: Copy vector table at memory addresses $0314-$0333 from or into user table");
        callsMap.put("ff90","SETMSG: Set system error display switch at memory address $009D");
        callsMap.put("ff93","LSTNSA: Send LISTEN secondary address to serial bus (must call LISTEN beforehands)");
        callsMap.put("ff96","TALKSA: Send TALK secondary address to serial bus (must call TALK beforehands)");
        callsMap.put("ff99","MEMBOT: Save or restore start address of BASIC work area");
        callsMap.put("ff9c","MEMTOP: Save or restore end address of BASIC work area");
        callsMap.put("ff9f","SCNKEY: Query keyboard; put current matrix code into memory address $00CB, current status of shift keys into memory address $028D and PETSCII code into keyboard buffer");
        callsMap.put("ffa2","SETTMO: Unknown (Set serial bus timeout)");
        callsMap.put("ffa5","IECIN: Read byte from serial bus (must call TALK and TALKSA beforehands)");
        callsMap.put("ffa8","IECOUT: Write byte to serial bus (must call LISTEN and LSTNSA beforehands)");
        callsMap.put("ffab","UNTALK: Send UNTALK command to serial bus");
        callsMap.put("ffae","UNLSTN: Send UNLISTEN command to serial bu");
        callsMap.put("ffb1","LISTEN: Send LISTEN command to serial bus");
        callsMap.put("ffb4","TALK: Send TALK command to serial bus");
        callsMap.put("ffb7","READST: Fetch status of current input/output device, value of ST variable (for RS232, status is cleared)");
        callsMap.put("ffba","SETLFS: Set file parameters");
        callsMap.put("ffbd","SETNAM: Set file name parameters");
        callsMap.put("ffc0","OPEN: Open file (must call SETLFS and SETNAM beforehands)");
        callsMap.put("ffc3","CLOSE: Close file");
        callsMap.put("ffc6","CHKIN: Define file as default input (must call OPEN beforehands)");
        callsMap.put("ffc9","CHKOUT: Define file as default output (must call OPEN beforehands)");
        callsMap.put("ffcc","CLRCHN: Close default input/output files (for serial bus, send UNTALK and/or UNLISTEN); restore default input/output to keyboard/screen");
        callsMap.put("ffcf","CHRIN: Read byte from default input (for keyboard, read a line from the screen). If not keyboard, must call OPEN and CHKIN beforehands");
        callsMap.put("ffd2","CHROUT: Write byte to default output (if not screen, must call OPEN and CHKOUT beforehands)");
        callsMap.put("ffd5","LOAD: Load or verify file (must call SETLFS and SETNAM beforehands)");
        callsMap.put("ffd8","SAVE: Save file (must call SETLFS and SETNAM beforehands)");
        callsMap.put("ffdb","SETTIM: Set Time of Day, at memory address $00A0-$00A2");
        callsMap.put("ffde","RDTIM: Read Time of Day, at memory address $00A0-$00A2");
        callsMap.put("ffe1","STOP: Query Stop key indicator, at memory address $0091; if pressed, call CLRCHN and clear keyboard buffer");
        callsMap.put("ffe4","GETIN: Read byte from default input (if not keyboard, must call OPEN and CHKIN beforehands)");
        callsMap.put("ffe7","CLALL: Clear file table; call CLRCHN");
        callsMap.put("ffea","UDTIM: Update Time of Day, at memory address $00A0-$00A2, and Stop key indicator, at memory address $0091");
        callsMap.put("ffed","SCREEN: Fetch number of screen rows and columns");
        callsMap.put("fff0","PLOT: Save or restore cursor position");
        callsMap.put("fff3","IOBASE: Fetch CIA #1 base address");

        //
        // Commodore 64 ROM
        //
        callsMap.put("a000","Basic cold start vector ($E394)");
        callsMap.put("a002","Basic warm start vector ($E37B)");
        callsMap.put("a004","Text 'cbmbasic'");
        callsMap.put("a00c","Addresses of the BASIC-commands -1 (END, FOR, NEXT, ... 35 addresses of 2 byte each)");
        callsMap.put("a052","Addresses of the BASIC functions (SGN, INT, ABS, ... 23 addresses of 2 byte each)");
        callsMap.put("a080","Hierarchy-codes and addresses of the operators -1 (10-times 1+2 Bytes)");
        callsMap.put("a09e","BASIC key words as string in PETSCII; Bit 7 of the last character is set");
        callsMap.put("a129","Keywords which have no action addresses - TAB(, TO, SPC(, ...; Bit 7 of the last character is set");
        callsMap.put("a140","Keywords of the operands + - * etc.; also AND, OR as strings. Bit 7 of the last character is set");
        callsMap.put("a14d","Keywords of the functions (SGN, INT, ABS, etc.) where bit 7 of the last character is set");
        callsMap.put("a19e","Error messages (TOO MANY FILES, FILE OPEN, ... ); 29 messages where bit 7 of the last character is set");
        callsMap.put("a328","Pointer-table to the error messages");
        callsMap.put("a364","Messages of the interpreter (OK, ERROR IN, READY, BREAK)");
        callsMap.put("a38a","Routine to search stack for FOR-NEXT and GOSUB");
        callsMap.put("a3b8","Called at BASIC line insertion. Checks, if enough space available. After completion, $A3BF is executed");
        callsMap.put("a3bf","Move bytes routine");
        callsMap.put("a3fb","Check for space on stack");
        callsMap.put("a408","Array area overflow check");
        callsMap.put("a435","Output of error message ?OUT OF MEMORY");
        callsMap.put("a437","Output of an error message, error number in X-register; uses vector in ($0300) to jump to $E38B");
        callsMap.put("a480","Input waiting loop; uses vector in ($0302) to jump to basic warm start at $A483");
        callsMap.put("a49c","Delete or Insert program lines and tokenize them");
        callsMap.put("a533","Re-link BASIC program");
        callsMap.put("a560","Input of a line via keyboard");
        callsMap.put("a579","Token crunch -> text line to interpreter code; uses vector in ($0304) to get to $A57C");
        callsMap.put("a613","Calculate start address of a program line");
        callsMap.put("a642","BASIC command NEW");
        callsMap.put("a65e","BASIC command CLR");
        callsMap.put("a68e","Set program pointer to BASIC-start (loads $7A, $7B with $2B-1, $2C-1)");
        callsMap.put("a69c","BASIC command LIST");
        callsMap.put("a717","Convert BASIC code to clear text; uses vector (0306) to jump to $A71A");
        callsMap.put("a742","BASIC-command FOR: Move 18 bytes to the stack 1) Pointer to the next instruction, 2) actual line number, 3) upper loop value, 4) step with (default value = 1), 5) name of the lop variable and 6) FOR-token.");
        callsMap.put("a7ae","Interpreter loop, set up next statement for execution");
        callsMap.put("a7c4","Check for program end");
        callsMap.put("a7e1","execute BASIC command; uses vector ($0308) to point to $A7E4");
        callsMap.put("a7ed","Executes BASIC keyword");
        callsMap.put("a81d","BASIC command RESTORE: set data pointer at $41, $42 to the beginning of the actual basic text");
        callsMap.put("a82c","BASIC command STOP (also END and program interruption)");
        callsMap.put("a82f","BASIC command STOP");
        callsMap.put("a831","BASIC command END");
        callsMap.put("a857","BASIC command CONT");
        callsMap.put("a871","BASIC command RUN");
        callsMap.put("a883","BASIC command GOSUB: Move 5 bytes to the stack. 1) the pointer within CHRGET, 2) the actual line number, 3) token of GOSUB; after that, GOTO ($a8a0) will be called");
        callsMap.put("a8a0","BASIC command GOTO");
        callsMap.put("a8d2","BASIC command RETURN");
        callsMap.put("a8f8","BASIC command DATA");
        callsMap.put("a906","Find offset of the next separator");
        callsMap.put("a928","BASIC command IF");
        callsMap.put("a93b","BASIC command REM");
        callsMap.put("a94b","BASIC command ON");
        callsMap.put("a96b","Get decimal number (0...63999, usually a line number) from basic text into $14/$15");
        callsMap.put("a9a5","BASIC command LET");
        callsMap.put("a9c4","Value assignment of integer");
        callsMap.put("a9d6","Value assignment of float");
        callsMap.put("a9d9","Value assignment of string");
        callsMap.put("a9e3","Assigns system variable TI$");
        callsMap.put("aa1d","Check for digit in string, if so, continue with $AA27");
        callsMap.put("aa27","Add PETSCII digit in string to float accumulator; Assumes C=0");
        callsMap.put("aa2c","Value assignment to string variable (LET for strings)");
        callsMap.put("aa80","BASIC command PRINT#");
        callsMap.put("aa86","BASIC command CMD");
        callsMap.put("aa9a","Part of the PRINT routine: Output string and continue with the handling of PRINT");
        callsMap.put("aaa0","BASIC command PRINT");
        callsMap.put("aab8","Outputs variable; Numbers will be converted into string first");
        callsMap.put("aaca","Append $00 as end indicator of string");
        callsMap.put("aad7","Outputs a CR/soft hyphenation (#$0D), followed by a line feed/newline (#$0A), if the channel number is 128");
        callsMap.put("aaf8","TAB( (C=1) and SPC( (C=0)");
        callsMap.put("ab1e","Output string: Output string, which is indicated by accu/Y reg, until 0 byte or quote is found");
        callsMap.put("ab3b","Output of cursor right (or space if output not on screen)");
        callsMap.put("ab3f","Output of a space character");
        callsMap.put("ab42","Output of cursor right");
        callsMap.put("ab45","Output of question mark (before error message)");
        callsMap.put("ab47","Output of a PETSCII character, accu must contain PETSCII value");
        callsMap.put("ab4d","Output error messages for read commands (INPUT / GET / READ)");
        callsMap.put("ab7b","BASIC command GET");
        callsMap.put("aba5","BASIC command INPUT#");
        callsMap.put("abbf","BASIC command INPUT");
        callsMap.put("abea","Get line into buffer");
        callsMap.put("abf9","Display input prompt");
        callsMap.put("ac06","BASIC commands READ, GET and INPUT share this routine and will be distinguished by a flag in $11");
        callsMap.put("ac35","Input routine for GET");
        callsMap.put("acfc","Messages ?EXTRA IGNORED and ?REDO FROM START, both followed by $0D (CR) and end of string $00.");
        callsMap.put("ad1d","BASIC command NEXT");
        callsMap.put("ad61","Check for valid loop");
        callsMap.put("ad8a","FRMNUM: Get expression (FRMEVL) and check, if numeric");
        callsMap.put("ad9e","FRMEVL: Analyzes any Basic formula expression and shows syntax errors. Set type flag $0D (Number: $00, string $FF). Set integer flag $0E (float: $00, integer: $80) puts values in FAC.");
        callsMap.put("ae83","EVAL: Get next element of an expression; uses vector ($030A) to jump to $AE86");
        callsMap.put("aea8","Value for constant PI in 5 bytes float format");
        callsMap.put("aef1","Evaluates expression within brackets");
        callsMap.put("aef7","Check for closed bracket ')'");
        callsMap.put("aefa","Check for open bracket '('");
        callsMap.put("aefd","Check for comma");
        callsMap.put("af08","Outputs error message ?SYNTAX ERROR and returns to READY state");
        callsMap.put("af0d","Calculates NOT");
        callsMap.put("af14","Check for reserved variables. Set carry flag, if FAC points to ROM. This indicates the use of one of the reserved variables TI$, TI, ST.");
        callsMap.put("af28","Get variable: Searches the variable list for one of the variables named in $45, $46");
        callsMap.put("af48","Reads clock counter and generate string, which contains TI$");
        callsMap.put("afa7","Calculate function: Determine type of function and evaluates it");
        callsMap.put("afb1","String function: check for open bracket, get expression (FRMEVL), checks for commas, get string.");
        callsMap.put("afd1","Analyze numeric function");
        callsMap.put("afe6","BASIC commands OR and AND, distinguished by flag $0B (= $FF at OR, $00 at AND).");
        callsMap.put("b016","Comparison (<, =, > )");
        callsMap.put("b01b","Numeric comparison");
        callsMap.put("b02e","String comparison");
        callsMap.put("b081","BASIC command DIM");
        callsMap.put("b08b","Check if variable name is valid");
        callsMap.put("b0e7","Searches variable in list, set variable pointer, create new variable, if name not found");
        callsMap.put("b113","Check for character");
        callsMap.put("b11d","Create variable");
        callsMap.put("b194","Calculate pointer to first element of array");
        callsMap.put("b1a5","Constant -32768 as float (5 bytes)");
        callsMap.put("b1aa","Convert FAC to integer and save it to accu/Y reg");
        callsMap.put("b1b2","Get positive integer from BASIC text");
        callsMap.put("b1bf","Convert FAC to integer");
        callsMap.put("b1d1","Get array variable from BASIC text");
        callsMap.put("b218","Search for array name in pointer ($45, $46)");
        callsMap.put("b245","Output error message ?BAD SUBSCRIPT");
        callsMap.put("b248","Output error message ?ILLEGAL QUANTITY");
        callsMap.put("b24d","Output error message ?REDIM\'D ARRAY");
        callsMap.put("b261","Create array variable");
        callsMap.put("b30e","Calculate address of a array element, set pointer ($47)");
        callsMap.put("b34c","Calculate distance of given array element to the one which ($47) points to and write the result to X reg/Y reg");
        callsMap.put("b37d","BASIC function FRE");
        callsMap.put("b391","Convert 16-bit integer in accu/Y reg to float");
        callsMap.put("b39e","BASIC function POS");
        callsMap.put("b3a2","Convert the byte in Y reg to float and return it to FAC");
        callsMap.put("b3a6","Check for direct mode: value $FF in flag $3A indicates direct mode");
        callsMap.put("b3ae","Output error message ?UNDEF\'D FUNCTION");
        callsMap.put("b3b3","BASIC command DEF FN");
        callsMap.put("b3e1","Check syntax of FN");
        callsMap.put("b3f4","BASIC function FN");
        callsMap.put("b465","BASIC function STR$");
        callsMap.put("b475","Make space for inserting into string");
        callsMap.put("b487","Get string, pointer in accu/Y reg");
        callsMap.put("b4ca","Store string pointer in descriptor stack");
        callsMap.put("b4f4","Reserve space for string, length in accu");
        callsMap.put("b526","Garbage Collection");
        callsMap.put("b606","Searches in simple variables and arrays for a string which has to be saved by the next Garbage Collection interation.");
        callsMap.put("b63d","Concatenates two strings");
        callsMap.put("b67a","Move String to reserved area");
        callsMap.put("b6a3","String management FRESTR");
        callsMap.put("b6db","Remove string pointer from descriptor stack");
        callsMap.put("b6ec","BASIC function CHR$");
        callsMap.put("b700","BASIC function LEFT$");
        callsMap.put("b72c","BASIC function RIGHT$");
        callsMap.put("b737","BASIC function MID$");
        callsMap.put("b761","String parameter from stack: Get pointer for string descriptor and write it to $50, $51 and the length to accu (also X-reg)");
        callsMap.put("b77c","BASIC function LEN");
        callsMap.put("b782","Get string parameter (length in Y-reg), switch to numeric");
        callsMap.put("b78b","BASIC function ASC");
        callsMap.put("b79b","Read and evaluate expression from BASIC text; the 1 byte value is then stored in X-reg and in FAC+4");
        callsMap.put("b7ad","BASIC function VAL");
        callsMap.put("b7eb","GETADR and GETBYT: Get 16-bit integer (to $14, $15) and an 8 bit value (to X-reg) - e.g. parameter for WAIT and POKE");
        callsMap.put("b7f7","Converts FAC in 2-byte integer (scope 0 ... 65535) to $14, $15 and Y-Reg/accu");
        callsMap.put("b80d","BASIC function PEEK");
        callsMap.put("b824","BASIC command POKE");
        callsMap.put("b82d","BASIC command WAIT");
        callsMap.put("b849","FAC = FAC + 0,5; for rounding");
        callsMap.put("b850","FAC = CONSTANT - FAC , accu and Y-register are pointing to CONSTANT (low and high byte)");
        callsMap.put("b853","FAC = ARG - FAC");
        callsMap.put("b862","Align exponent of FAC and ARG for addition");
        callsMap.put("b867","FAC = CONSTANT (accu/Y reg) + FAC");
        callsMap.put("b86a","FAC = ARG + FAC");
        callsMap.put("b947","Invert mantissa of FAC");
        callsMap.put("b97e","Output error message OVERFLOW");
        callsMap.put("b983","Multiplies with one byte");
        callsMap.put("b9bc","Constant 1.00 (table of constants in extended floating point format for LOG)");
        callsMap.put("b9c1","Constant 03 (grade of polynome, then 4th coefficient)");
        callsMap.put("b9c2","Constant 0.434255942 (1st coefficient)");
        callsMap.put("b9c7","Constant 0.576584541 (2nd coefficient)");
        callsMap.put("b9cc","Constant 0.961800759 (3rd coefficient)");
        callsMap.put("b9d1","Constant 2.885390073 (4th coefficient)");
        callsMap.put("b9d6","Constant 0.707106781 = 1/SQR(2)");
        callsMap.put("b9db","Constant 1.41421356 = SQR(2)");
        callsMap.put("b9e0","Constant -0.5");
        callsMap.put("b9e5","Constant 0.693147181 = LOG(2)");
        callsMap.put("b9ea","BASIC-function LOG");
        callsMap.put("ba28","FAC = constant (accu/Y reg) * FAC");
        callsMap.put("ba30","FAC = ARG * FAC");
        callsMap.put("ba59","Multiplies FAC with one byte and stores result to $26 .. $2A");
        callsMap.put("ba8c","ARG = constant (accu/Y reg)");
        callsMap.put("bab7","Checks FAC and ARG");
        callsMap.put("bae2","FAC = FAC * 10");
        callsMap.put("baf9","Constant 10 as extended floating point format");
        callsMap.put("bafe","FAC = FAC / 10");
        callsMap.put("bb0f","FAC = constant (accu/Y reg) / FAC");
        callsMap.put("bb14","FAC = ARG / FAC");
        callsMap.put("bb8a","Output error message ?DIVISION BY ZERO");
        callsMap.put("bba2","Transfer constant (accu/Y reg) to FAC");
        callsMap.put("bbc7","FAC to accu #4 ($5C to $60)");
        callsMap.put("bbca","FAC to accu #3 ($57 to $5B)");
        callsMap.put("bbd0","FAC to variable (the address, where $49 points to)");
        callsMap.put("bbfc","ARG to FAC");
        callsMap.put("bc0c","FAC (rounded) to ARG");
        callsMap.put("bc1b","Rounds FAC");
        callsMap.put("bc2b","Get sign of FAC: A=0 if FAC=0, A=1 if FAC positive, A=$FF if FAC negative");
        callsMap.put("bc39","BASIC function SGN");
        callsMap.put("bc58","BASIC function ABS");
        callsMap.put("bc5b","Compare constant (accu/Y reg) with FAC: A=0 if equal, A=1 if FAC greater, A=$FF if FAC smaller");
        callsMap.put("bc9b","FAC to integer: converts FAC to 4-byte integer");
        callsMap.put("bccc","BASIC function INT");
        callsMap.put("bcf3","Conversion PETSCII string to floating-point format");
        callsMap.put("bdb3","Constant 9999999.9 (3 constants for float PETSCII conversion)");
        callsMap.put("bdb8","Constant 99999999");
        callsMap.put("bdbd","Constant 1000000000");
        callsMap.put("bdc2","Output of 'IN' and line number (from CURLIN $39, $3A)");
        callsMap.put("bdcd","Output positive integer number in accu/X reg");
        callsMap.put("bddd","Convert FAC to PETSCII string which starts with $0100 and ends with $00. Start address in accu/Y reg.");
        callsMap.put("be68","TI to string: convert TI to PETSCII string which starts with $0100 and ends with $00");
        callsMap.put("bf11","Constant 0.5");
        callsMap.put("bf16","Constant tables for integer PETSCII conversion");
        callsMap.put("bf3a","Constant tables to convert TI to TI$");
        callsMap.put("bf71","BASIC function SQR");
        callsMap.put("bf78","Power function FAC = ARG to the power of constant (accu/Y reg)");
        callsMap.put("bf7b","Power function FAC = ARG to the power of FAC");
        callsMap.put("bfb4","Makes FAC negative");
        callsMap.put("bfbf","Constant 1.44269504 = 1/LOG(2) (table of 8 constants to evaluate EXP - polynomal table)");
        callsMap.put("bfc4","Constant 07: 7 = Grade of polynome (followed by 8 coefficient constants)");
        callsMap.put("bfc5","Constant 2.149875 E-5");
        callsMap.put("bfca","Constant 1.435231 E-4");
        callsMap.put("bfcf","Constant 1.342263 E-3");
        callsMap.put("bfd4","Constant 9.641017 E-3");
        callsMap.put("bfd9","Constant 5.550513 E-2");
        callsMap.put("bfde","Constant 2.402263 E-4");
        callsMap.put("bfe3","Constant 6.931471 E-1");
        callsMap.put("bfe8","Constant 1.00");
        callsMap.put("bfed","BASIC function EXP");      
    }
}