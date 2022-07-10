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
// Search for know Commodore 1541 ROM calls and add a comment with the description of 
// the call itself.
// 
// Sources used to map the calls:
// https://ist.uwaterloo.ca/~schepers/MJK/ascii/1541map.txt
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

public class FindC1541ROMCalls extends GhidraScript {
    
    private int debug = 0;
    Map<String, String> callsMap = new HashMap<String, String>();

    @Override
    public void run() throws Exception {

        println("*** - FindC1541ROMCalls - Starting...");
        
        Address addr = currentProgram.getMemory().getMinAddress();
        PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);

        AddressSetView execSet = currentProgram.getMemory().getExecuteSet();
        AddressSet disSet = new AddressSet();

        // Load mapping
        loadROMCallMap();

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
        println("*** - FindC1541ROMCalls - End");
    }
    
    private void loadROMCallMap() {

        //
        // Commodore 1541 ROM
        //
        callsMap.put("c100","Turn LED on for current drive");
        callsMap.put("c118","Turn LED on");
        callsMap.put("c123","Clear error flags");
        callsMap.put("c12c","Prepare for LED flash after error");
        callsMap.put("c146","Interpret command from computer");
        callsMap.put("c194","Prepare error msg after executing command");
        callsMap.put("c1bd","Erase input buffer");
        callsMap.put("c1c8","Output error msg (track and sector 0)");
        callsMap.put("c1d1","Check input line");
        callsMap.put("c1e5","Check ':' on input line");
        callsMap.put("c1ee","Check input line");
        callsMap.put("c268","Search character in input buffer");
        callsMap.put("c2b3","Check line length");
        callsMap.put("c2dc","Clear flags for command input");
        callsMap.put("c312","Preserve drive number");
        callsMap.put("c33c","Search for drive number");
        callsMap.put("c368","Get drive number");
        callsMap.put("c38f","Reverse drive number");
        callsMap.put("c398","Check given file type");
        callsMap.put("c3bd","Check given drive number");
        callsMap.put("c3ca","Verify drive number");
        callsMap.put("c44f","Search for file in directory");
        callsMap.put("c63d","Test and initalise drive");
        callsMap.put("c66e","Name of file in directory buffer");
        callsMap.put("c688","Copy filename to work buffer");
        callsMap.put("c6a6","Search for end of name in command");
        callsMap.put("c7ac","Clear Directory Output Buffer");
        callsMap.put("c7b7","Create header with disk name");
        callsMap.put("c806","Print 'blocks free.'");
        callsMap.put("c823","Perform [S] - Scratch command");
        callsMap.put("c87d","Erase file");
        callsMap.put("c8b6","Erase dir entry");
        callsMap.put("c8c1","Perform [D] - Backup command (Unused)");
        callsMap.put("c8c6","Format disk");
        callsMap.put("c8f0","Perform [C] - Copy command");
        callsMap.put("ca88","Perform [R] - Rename command");
        callsMap.put("cacc","Check if file present");
        callsMap.put("caf8","Perform [M] - Memory command");
        callsMap.put("cb20","M-R memory read");
        callsMap.put("cb50","M-W memory write");
        callsMap.put("cb5c","Perform [U] - User command");
        callsMap.put("cb84","Open direct access channel, number");
        callsMap.put("cc1b","Perform [B] - Block/Buffer command");
        callsMap.put("cc6f","Get parameters form block commands");
        callsMap.put("ccf5","B-F block free");
        callsMap.put("cd03","B-A block allocate");
        callsMap.put("cd36","Read block to buffer");
        callsMap.put("cd3c","Get byte from buffer");
        callsMap.put("cd42","Read block from disk");
        callsMap.put("cd56","B-R block read");
        callsMap.put("cd5f","U1, Block read without changing buffer pointer");
        callsMap.put("cd73","B-W block write");
        callsMap.put("cd97","U2, Block write without changing buffer pointer");
        callsMap.put("cda3","B-E block execute");
        callsMap.put("cdbd","B-P block pointer");
        callsMap.put("cdd2","Open channel");
        callsMap.put("cdf2","Check buffer number and open channel");
        callsMap.put("ce0e","Set pointer for REL file");
        callsMap.put("ce6e","Divide by 254");
        callsMap.put("ce71","Divide by 120");
        callsMap.put("ced9","Erase work storage");
        callsMap.put("cee2","Left shift 3-byte register twice");
        callsMap.put("cee5","Left shift 3-byte register once");
        callsMap.put("ceed","Add 3-byte registers");
        callsMap.put("cf8c","Change buffer");
        callsMap.put("cf9b","Write data in buffer");
        callsMap.put("cff1","Write data byte in buffer");
        callsMap.put("d005","Perform [I] - Initalise command");
        callsMap.put("d00e","Read BAM from disk");
        callsMap.put("d042","Load BAM");
        callsMap.put("d075","Calculate blocks free");
        callsMap.put("d0c3","Read block");
        callsMap.put("d0c7","Write block");
        callsMap.put("d0eb","Open channel for reading");
        callsMap.put("d107","Open channel for writing");
        callsMap.put("d125","Check for file type REL");
        callsMap.put("d12f","Get buffer and channel numbers");
        callsMap.put("d137","Get a byte from buffer");
        callsMap.put("d156","Get byte and read next block");
        callsMap.put("d19d","Write byte in buffer and block");
        callsMap.put("d1c6","Increment buffer pointer");
        callsMap.put("d1d3","Get drive number");
        callsMap.put("d1df","Find write channel and buffer");
        callsMap.put("d1e2","Find read channel and buffer");
        callsMap.put("d227","Close channel");
        callsMap.put("d25a","Free buffer");
        callsMap.put("d28e","Find buffer");
        callsMap.put("d307","Close all channels");
        callsMap.put("d313","Close all channels of other drives");
        callsMap.put("d37f","Find channel and allocate");
        callsMap.put("d39b","Get byte for output");
        callsMap.put("d44d","Read next block");
        callsMap.put("d460","Read block");
        callsMap.put("d464","Write block");
        callsMap.put("d475","Allocate buffer and read block");
        callsMap.put("d486","Allocate new block");
        callsMap.put("d48d","Write dir block");
        callsMap.put("d4c8","Set buffer pointer");
        callsMap.put("d4da","Close internal channel");
        callsMap.put("d4e8","Set buffer pointer");
        callsMap.put("d4f6","Get byte from buffer");
        callsMap.put("d506","Check track and sector numbers");
        callsMap.put("d552","Get track and sector numbers for current job");
        callsMap.put("d55f","Check for vaild track and sector numbers");
        callsMap.put("d572","DOS mismatch error");
        callsMap.put("d586","Read block");
        callsMap.put("d58a","Write block");
        callsMap.put("d599","Verify execution");
        callsMap.put("d5c6","Additional attempts for read errors");
        callsMap.put("d676","Move head by half a track");
        callsMap.put("d693","Move head one track in or out");
        callsMap.put("d6a6","Attempt command execution multiple times");
        callsMap.put("d6d0","Transmit param to disk controller");
        callsMap.put("d6e4","Enter file in dir");
        callsMap.put("d7b4","OPEN command, secondary addr 15");
        callsMap.put("d7c7","-Check '*' Last file");
        callsMap.put("d7f3","-Check '$' Directory");
        callsMap.put("d815","-Check '#' Channel");
        callsMap.put("d8f5","Open a file with overwriting (@)");
        callsMap.put("d9a0","Open file for reading");
        callsMap.put("d9e3","Open file for writing");
        callsMap.put("da09","Check file type and control mode");
        callsMap.put("da2a","Preparation for append");
        callsMap.put("da55","Open directory");
        callsMap.put("dac0","Close routine");
        callsMap.put("db02","Close file");
        callsMap.put("db62","Write last block");
        callsMap.put("dba5","Directory entry");
        callsMap.put("dc46","Read block, allocate buffer");
        callsMap.put("dcb6","Reset pointer");
        callsMap.put("dcda","Construct a new block");
        callsMap.put("dd8d","Write byte in side-sector block");
        callsMap.put("dd95","Manipulate flags");
        callsMap.put("ddab","Verify command code for writing");
        callsMap.put("ddf1","Write a block of a REL file");
        callsMap.put("ddfd","Write bytes for following track");
        callsMap.put("de0c","Get following track and sector numbers");
        callsMap.put("de19","Following track for last block");
        callsMap.put("de2b","buffer pointer to zero");
        callsMap.put("de3b","Get track and sector");
        callsMap.put("de95","Get following track and sector from buffer");
        callsMap.put("dea5","Copy buffer contents");
        callsMap.put("dec1","Erase buffer Y");
        callsMap.put("ded2","Get side-sector number");
        callsMap.put("dedc","Set buffer pointer to side-sector");
        callsMap.put("dee9","Buffer pointer for side-sector");
        callsMap.put("def8","Get side sector and buffer pointer");
        callsMap.put("df1b","Read side-sector");
        callsMap.put("df21","Write side-sector");
        callsMap.put("df45","Set buffer pointer in side-sector");
        callsMap.put("df4c","Calculate number of blocks in a REL file");
        callsMap.put("df66","Verify side-sector in buffer");
        callsMap.put("df93","Get buffer number");
        callsMap.put("dfd0","Get next record iin REL file");
        callsMap.put("e03c","Write block and read next block");
        callsMap.put("e07c","Write a byte in a record");
        callsMap.put("e0ab","Write byte in REL file");
        callsMap.put("e0f3","Fill record with 0s");
        callsMap.put("e105","Write buffer number in table");
        callsMap.put("e120","Get byte from REL file");
        callsMap.put("e1cb","Get last side-sector");
        callsMap.put("e207","Perform [P] - Position command");
        callsMap.put("e2e2","Divide data blocks into records");
        callsMap.put("e304","Set pointer to next record");
        callsMap.put("e31c","Expand side-sector");
        callsMap.put("e44e","Write side-sector and allocate new");
        callsMap.put("e60a","Prepare error number and message");
        callsMap.put("e645","Print error message into error buffer");
        callsMap.put("e680","TALK");
        callsMap.put("e688","LISTEN");
        callsMap.put("e69b","Convert BIN to 2-Ascii (error message buffer)");
        callsMap.put("e6ab","Convert BCD to 2-Ascii (error message buffer)");
        callsMap.put("e6bc","Write OK in buffer");
        callsMap.put("e6c1","Print error on track 00,00 to error buffer");
        callsMap.put("e6c7","Print error on current track to error buffer");
        callsMap.put("e706","Write error message string to buffer");
        callsMap.put("e754","Get character and in buffer");
        callsMap.put("e767","Get a char of the error message");
        callsMap.put("e775","Increment pointer");
        callsMap.put("e77f","Dummy subroutine");
        callsMap.put("e780","Check for auto start - removed");
        callsMap.put("e7a3","Perform [&] - USR file execute command");
        callsMap.put("e84b","Generate checksum");
        callsMap.put("e853","IRQ routine for serial bus");
        callsMap.put("e85b","Service the serial bus");
        callsMap.put("e909","Send data");
        callsMap.put("e99c","DATA OUT lo");
        callsMap.put("e9a5","DATA OUT hi");
        callsMap.put("e9ae","CLOCK OUT hi");
        callsMap.put("e9b7","CLOCK OUT lo");
        callsMap.put("e9c0","Read IEEE port");
        callsMap.put("e9c9","Get data byte from bus");
        callsMap.put("e9f2","Accept byte with EOI");
        callsMap.put("ea2e","Accept data from serial bus");
        callsMap.put("ea59","Test for ATN");
        callsMap.put("ea6e","Flash LED for hardware defects, self-test");
        callsMap.put("eaa0","Power-up RESET routine");
        callsMap.put("ebff","Wait loop");
        callsMap.put("ec9e","Load dir");
        callsMap.put("ed59","Transmit dir line");
        callsMap.put("ed67","Get byte from buffer");
        callsMap.put("ed84","Perform [V] - Validate command");
        callsMap.put("ede5","Allocate file blocks in BAM");
        callsMap.put("ee0d","Perform [N] - New (Format) command");
        callsMap.put("eeb7","Create BAM");
        callsMap.put("eef4","Write BAM if needed");
        callsMap.put("ef3a","Set buffer pointer for BAM");
        callsMap.put("ef4d","Get number of free blocks for dir");
        callsMap.put("ef5c","Mark block as free");
        callsMap.put("ef88","Set flag for BAM changed");
        callsMap.put("ef90","Mark block as allocated");
        callsMap.put("efcf","Erase bit for sector in BAM entry");
        callsMap.put("eff1","Write BAM after change");
        callsMap.put("f005","Erase BAM buffer");
        callsMap.put("f0d1","Clear BAM ?");
        callsMap.put("f10f","Get buffer number for BAM");
        callsMap.put("f119","Buffer number for BAM");
        callsMap.put("f11e","Find and allocate free block");
        callsMap.put("f1a9","Find free sector and allocate");
        callsMap.put("f1fa","Find free sectors in current track");
        callsMap.put("f220","Verify number of free blocks in BAM");
        callsMap.put("f24b","Establish number of sectors per track");
        callsMap.put("f258","Dummy subroutine");
        callsMap.put("f259","Initialise disk controller");
        callsMap.put("f2b0","IRQ routine for disk controller");
        callsMap.put("f2f9","Head transport");
        callsMap.put("f36e","Execute program in buffer");
        callsMap.put("f37c","Bump, find track 1 (head at stop)");
        callsMap.put("f393","Initialise pointer in buffer");
        callsMap.put("f3b1","Read block header, verify ID");
        callsMap.put("f410","Preserve block header");
        callsMap.put("f418","Work Return value 01 (OK) into queue");
        callsMap.put("f41b","Work Return value 0B (READ ERROR) into queue");
        callsMap.put("f41e","Work Return value 09 (READ ERROR) into queue");
        callsMap.put("f423","Job optimisation");
        callsMap.put("f4ca","Test command code further");
        callsMap.put("f4d1","Read sector");
        callsMap.put("f50a","Find start of data block");
        callsMap.put("f510","Read block header");
        callsMap.put("f556","Wait for SYNC");
        callsMap.put("f56e","Test command code further");
        callsMap.put("f575","Write data block to disk");
        callsMap.put("f5e9","Calculate parity for data buffer");
        callsMap.put("f5f2","Convert buffer of GCR data into binary");
        callsMap.put("f691","Test command code further");
        callsMap.put("f698","Compare written data with data on disk");
        callsMap.put("f6ca","Command code for find sector");
        callsMap.put("f6d0","Convert 4 binary bytes to 5 GCR bytes");
        callsMap.put("f78f","Convert 260 bytes to 325 bytes group code");
        callsMap.put("f7e6","Convert 5 GCR bytes to 4 binary bytes");
        callsMap.put("f8a0","Conversion table GCR to binary - high nybble");
        callsMap.put("f8c0","Conversion table GCR to binary - low nybble");
        callsMap.put("f8e0","Decode 69 GCR bytes");
        callsMap.put("f934","Convert block header to GCR code");
        callsMap.put("f969","Error entry disk controller");
        callsMap.put("f97e","Turn drive motor on");
        callsMap.put("f98f","Turn drive motor off");
        callsMap.put("f99c","Job loop disk controller");
        callsMap.put("fa05","Move head to next track");
        callsMap.put("fa1c","Calculate number of head steps");
        callsMap.put("fa3b","Move stepper motor short distance");
        callsMap.put("fa4e","Load head");
        callsMap.put("fa7b","Prepare fast head movement");
        callsMap.put("fa97","Fast head movement");
        callsMap.put("faa5","Prepare slow head movement");
        callsMap.put("fac7","Formatting");
        callsMap.put("fda3","Write SYNC 10240 times, erase track");
        callsMap.put("fdc3","Read/write ($621/$622) times");
        callsMap.put("fdd3","Attempt counter for formatting");
        callsMap.put("fdf5","Copy data from overflow buffer");
        callsMap.put("fe00","Switch to reading");
        callsMap.put("fe0e","Write $55 10240 times");
        callsMap.put("fe30","Convert header in buffer 0 to GCR code");
        callsMap.put("fe67","Interrupt routine");
        callsMap.put("fee7","From UI command $EB22, to reset");
        callsMap.put("feea","Patch for diagnostic routine from $EA7A");
        callsMap.put("fef3","Delay loop for serial bus in 1541 mode, from $E97D");
        callsMap.put("fefb","Patch for data output to serial bus, from $E980");
        callsMap.put("ff01","U9 vector, switch 1540/1541");
        callsMap.put("ff10","Patch for reset routine, from $EAA4");
        callsMap.put("ff20","Patch for listen to serial bus, from $E9DC");
    }
}