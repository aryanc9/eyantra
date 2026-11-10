/*
* Logic Quest (LQ): Task 3A Path Planner with Decryption
*
* Computes the shortest path on the Logic Quest arena (nodes N1..N36), with the
* line weights of Figure 1 on the Task 3A page: straight line 5, ring arcs
* 7 / 11 / 15 / 19 (inner ring to outermost ring), wavy line N1-N36 100.
*
* Inputs : current_node, next_node, is_encrypted
*   current_node     : where the bot is, 1..36. The path starts here.
*                      At the first location the bot is in the start box, N35.
*   is_encrypted = 0 : next_node is a node number.
*                      Path: current_node -> next_node.
*   is_encrypted = 1 : next_node is the 8-byte encrypted code, encrypted with
*                      PRESENT-80.
*                      Path: current_node -> the drop node in the block.
*
* Decrypted code (8 bytes, byte 0 first):
*   byte 0     : done flag (1 = last block: no pick-up after this drop)
*   byte 1..5  : message, 5 ASCII characters (0x00 = no character)
*   byte 6     : next pick-up node 1..36 (not used when the done flag is 1)
*   byte 7     : drop node 1..36 for this block
*   e.g. message "HELLO", drop at N26, then pick up at N12
*        -> 00 48 45 4C 4C 4F 0C 1A = 0048454C4C4F0C1A
*
* Outputs:
*   is_encrypted = 0 : the path from current_node to next_node.
*   is_encrypted = 1 : the message (message[]) and the path from current_node
*                      to the drop node. When the done flag is 0, the inputs
*                      for the next run are written too:
*                          IS_ENCRYPTED = 0
*                          CURRENT_NODE = the drop node
*                          NEXT_NODE    = the next pick-up node
*                      When the done flag is 1, the inputs are left as they are.
*
* Output (PC), read by test.sh line by line:
*   is_encrypted = 0     is_encrypted = 1, done = 0     is_encrypted = 1, done = 1
*   35                   Message : HELLO                Message : BYE
*   ...                  7                              7
*   7                    ...                            ...
*                        26                             26
*                        Next current_node : 26         Done
*                        Next next_node : 12
*   The path is one node per line, first node first. The message line shows
*   the non-zero message bytes as characters. The code at the end of main
*   prints all of this from message[], path_planned[], idx and the inputs
*   written for the next run.
*
* Debug prints: start every debug line with "dbg:" (see Functions Usage
*   below). test.sh and the evaluator skip the lines that start with "dbg:".
*   Any other extra line counts as part of your output and makes it wrong.
*
* PRESENT-80 (the cipher used for the encrypted codes):
*   block 64 bits, key 80 bits = A1 B2 C3 D4 E5 F6 07 18 29 3A (PRESENT_KEY_* below),
*   31 rounds. See the Task 3A page for the full description of the encryption;
*   your program has to do the reverse.
*
* Data memory ranges (used on the RISC-V CPU, Task 3B):
*   0x02000000 .. 0x0200000F : inputs
*   0x02000010 .. 0x0200001F : outputs (0x0200001C = CPU_DONE)
*   0x02000020 and up        : working memory, stack at the top
*
* Inputs  : ENCRYPTED_HI (0x02000000)  encrypted block, bytes 0..3 (first 8 hex digits)
*           ENCRYPTED_LO (0x02000004)  encrypted block, bytes 4..7 (last 8 hex digits)
*           IS_ENCRYPTED (0x02000008)  0 or 1                            } written for
*           NEXT_NODE    (0x0200000C)  next node, when IS_ENCRYPTED = 0   } the next run
*           CURRENT_NODE (0x0200000D)  current node (where the bot is)    } when done = 0
* Outputs : MESSAGE_0..4 (0x02000010 .. 0x02000014)  message, block bytes 1..5
*           NODE_POINT   (0x02000018)  every node of the path, written in order
*           CPU_DONE     (0x0200001C)  = 1 when finished
*
* Make sure you don't change anything outside the "Add your code here" sections.
*/

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

// PRESENT-80 key: A1 B2 C3 D4 E5 F6 07 18 29 3A
#define PRESENT_KEY_HI  0xA1B2C3D4   // key bits 79..48
#define PRESENT_KEY_MID 0xE5F60718   // key bits 47..16
#define PRESENT_KEY_LO  0x293A       // key bits 15..0

#ifdef __linux__ // for host pc

    #include <stdio.h>

    void _put_byte(char c) { putchar(c); }

    void _put_str(char *str) {
        while (*str) {
            _put_byte(*str++);
        }
    }

    void print_output(uint8_t num) {
        if (num == 0) {
            putchar('0'); // if the number is 0, directly print '0'
            _put_byte('\n');
            return;
        }

        // convert the integer to a string
        char buffer[20];
        uint8_t index = 0;

        while (num > 0) {
            buffer[index++] = '0' + num % 10; // convert the last digit to its character representation
            num /= 10;                        // move to the next digit
        }
        // print the characters in reverse order (from right to left)
        while (index > 0) { putchar(buffer[--index]); }
        _put_byte('\n');
    }

    void _put_value(uint8_t val) { print_output(val); }

    // print a 32-bit value as 8 hex digits and a newline (e.g. the decrypted block)
    void _put_hex(uint32_t val) { printf("%08X\n", (unsigned int)val); }

    // read 16 hex digits into two 32-bit words, returns 0 if the text is not 16 hex digits
    int read_block(const char *hex, uint32_t *hi, uint32_t *lo) {
        uint32_t word[2] = { 0, 0 };
        if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
        for (int n = 0; n < 16; n++) {
            char c = hex[n];
            uint32_t d;
            if      (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return 0;
            word[n >> 3] = (word[n >> 3] << 4) | d;
        }
        if (hex[16] != '\0') return 0;
        *hi = word[0];
        *lo = word[1];
        return 1;
    }

    /*
     * On the PC there is no data memory at 0x02000000, so MEM32(address) is a
     * normal array (one entry per 32-bit word). On the CPU it is the real
     * data memory. Either way, MEM32(0x02000020) reads the same place.
     */
    static uint32_t pc_data_mem[128];
    #define MEM32(addr)  (pc_data_mem[((addr) - 0x02000000u) >> 2])

#else  // for the test device

    void _put_byte(char c) { }
    void _put_value(uint8_t val) { }
    void _put_hex(uint32_t val) { }
    void _put_str(char *str) { }

    #define MEM32(addr)  (*(volatile uint32_t *)(addr))

#endif

/*
Functions Usage

To print while debugging, use the functions below, not printf().
On the PC they print. On the CPU they are empty, so they cost nothing there
and the same file still builds with generatehex.sh.

for a character: _put_byte('A');                        (putchar() on the PC)
for newline:     _put_byte('\n');
for string:      _put_str("your string here");
for number:      _put_value(your_number_here);           0 to 255, then a newline
for 32 bits:     _put_hex(your_32_bit_value_here);       8 hex digits, then a newline

Start every debug line with "dbg:" and end it with a newline (_put_value
and _put_hex end the line for you). test.sh and the evaluator skip the
lines that start with "dbg:", so these prints can stay in the file you
submit. Any other line you print counts as part of your output (see
"Output (PC)" at the top) and makes it wrong.

Examples:
        _put_str("dbg: start_point = ");     _put_value(start_point);
        _put_str("dbg: end_point = ");       _put_value(end_point);
        _put_str("dbg: ENCRYPTED_HI = ");    _put_hex(ENCRYPTED_HI);    // encrypted block, bytes 0..3
        _put_str("dbg: ENCRYPTED_LO = ");    _put_hex(ENCRYPTED_LO);    // encrypted block, bytes 4..7
        _put_str("dbg: first character = "); _put_byte(message[0]); _put_byte('\n');
        _put_str("dbg: Hello World!\n");

*/

// Custom Functions

// ############# Add your code here #############

// add your own #defines and functions here
// (e.g. the PRESENT-80 decryption and the path planner)

// ---------------------------------------------------------------------------
// Team ID:          6100
// Theme:            Logic Quest
// Author List:      Shraddha Velapurkar, Aryan Chopare, Ajinkya Darekar, Aarti Batagi
// Filename:         Path_Planner_Dec.c
// File Description: PRESENT-80 decryption and shortest-path planning on the
//                   Logic Quest arena (Bellman-Ford run from the end node; the arena lines live in code, not RAM)
// Global variables: None
// ---------------------------------------------------------------------------

// sbox: PRESENT S-box, packed as two 32-bit numbers (no array stored in the program)
static uint32_t sbox(uint32_t x) {
    return (x < 8) ? (0xDA09B65Cu >> (x << 2)) & 0xFu
                   : (0x21748FE3u >> ((x - 8) << 2)) & 0xFu;
}

// isbox: inverse of sbox, packed the same way
static uint32_t isbox(uint32_t x) {
    return (x < 8) ? (0xD21C8FE5u >> (x << 2)) & 0xFu
                   : (0xA970364Bu >> ((x - 8) << 2)) & 0xFu;
}

// rotl1: rotates the 80-bit key register r[2]:r[1]:r[0] left by one bit
// (r[2] holds bits 79..64, r[1] bits 63..32, r[0] bits 31..0)
static void rotl1(uint32_t *r) {
    uint32_t top = (r[2] >> 15) & 1u;
    r[2] = ((r[2] << 1) | (r[1] >> 31)) & 0xFFFFu;
    r[1] = (r[1] << 1) | (r[0] >> 31);
    r[0] = (r[0] << 1) | top;
}

// key_fwd: one key schedule step forwards (rotate left 61, S-box, XOR counter i)
static void key_fwd(uint32_t *r, uint32_t i) {
    uint32_t n;
    for (n = 0; n < 61; n++) rotl1(r);
    r[2] = (r[2] & 0x0FFFu) | (sbox(r[2] >> 12) << 12);
    r[0] ^= (i << 15);                       // bits 19..15
}

// key_back: undoes key_fwd (XOR counter i, inverse S-box, rotate left 19 = right 61)
static void key_back(uint32_t *r, uint32_t i) {
    uint32_t n;
    r[0] ^= (i << 15);
    r[2] = (r[2] & 0x0FFFu) | (isbox(r[2] >> 12) << 12);
    for (n = 0; n < 19; n++) rotl1(r);
}

// add_key: XORs the state s[0] (hi) : s[1] (lo) with the round key = register bits 79..16
static void add_key(uint32_t *s, const uint32_t *r) {
    s[0] ^= (r[2] << 16) | (r[1] >> 16);
    s[1] ^= (r[1] << 16) | (r[0] >> 16);
}

// inv_sub: inverse S-box layer on all 16 nibbles
static void inv_sub(uint32_t *s) {
    uint32_t w, k, v;
    for (w = 0; w < 2; w++) {
        v = 0;
        for (k = 0; k < 8; k++) v |= isbox((s[w] >> (k << 2)) & 0xFu) << (k << 2);
        s[w] = v;
    }
}

// inv_perm: inverse P-layer. P(i) = 16*i mod 63 is stepped by adding 16
// (no multiply or remainder); output bit i = input bit P(i); bit 63 stays
static void inv_perm(uint32_t *s) {
    uint32_t i, p = 0, o0 = 0, o1 = 0, b;
    for (i = 0; i < 63; i++) {
        b = (p < 32) ? ((s[1] >> p) & 1u) : ((s[0] >> (p - 32)) & 1u);
        if (i < 32) o1 |= b << i; else o0 |= b << (i - 32);
        p += 16;
        if (p >= 63) p -= 63;
    }
    o0 |= s[0] & 0x80000000u;
    s[0] = o0;
    s[1] = o1;
}

// present_decrypt: decrypts s[0] (bytes 0..3) : s[1] (bytes 4..7) in place.
// The key is given as the boilerplate's three words (bits 79..48, 47..16, 15..0).
// r[0..2] is scratch space for the 80-bit key register (given by the caller so
// it can share memory). The key schedule is run forwards to K32, then stepped
// backwards, so the 32 round keys are never stored.
static void present_decrypt(uint32_t *s, uint32_t *r, uint32_t key_hi, uint32_t key_mid, uint32_t key_lo) {
    uint32_t i;
    r[2] = key_hi >> 16;
    r[1] = (key_hi << 16) | (key_mid >> 16);
    r[0] = (key_mid << 16) | key_lo;
    for (i = 1; i < 32; i++) key_fwd(r, i);  // register now gives K32
    add_key(s, r);
    for (i = 31; i >= 1; i--) {
        inv_perm(s);
        inv_sub(s);
        key_back(r, i);                      // register now gives K_i
        add_key(s, r);
    }
}

// edge_weight: weight class -> line weight, using shifts only
// weight class c: 0 = straight 5, 1 = inner arc 7, 2 = middle arc 11,
//                 3 = outer arc 15, 4 = outermost arc 19, 5 = wavy line 100
static uint32_t edge_weight(uint32_t c) {
    return (c == 5) ? 100u : (c ? (3u + (c << 2)) : 5u);
}

// edge_op: works on one arena line, packed as (u << 9) | (v << 3) | weight class.
// cur == 0 : relax the line in both directions (dist[0] is set to 1 if any
//            distance improved; dist[0] is not a node, so it is used as a flag)
// cur != 0 : returns the node on the other end of the line if it is one step
//            closer to the end node than cur, otherwise 0
static uint32_t edge_op(uint8_t *dist, uint32_t cur, uint32_t e) {
    uint32_t u = e >> 9, v = (e >> 3) & 63u, w = edge_weight(e & 7u);
    if (cur == 0) {
        if (dist[v] != 255 && dist[v] + w < dist[u]) { dist[u] = dist[v] + w; dist[0] = 1; }
        if (dist[u] != 255 && dist[u] + w < dist[v]) { dist[v] = dist[u] + w; dist[0] = 1; }
        return 0;
    }
    if (u == cur && dist[v] != 255 && dist[v] + w == dist[cur]) return v;
    if (v == cur && dist[u] != 255 && dist[u] + w == dist[cur]) return u;
    return 0;
}

// EDGE: visits one arena line (nodes u, v, weight class c). Once a line has
// returned a node, the remaining lines are skipped (relax mode always returns 0)
#define EDGE(u, v, c) if (!r) r = edge_op(dist, cur, ((u) << 9) | ((v) << 3) | (c));

// scan_edges: visits all 37 lines of the arena. The line list is part of the
// program, so it uses no data memory.
static uint32_t scan_edges(uint8_t *dist, uint32_t cur) {
    uint32_t r = 0;
    EDGE(1, 36, 5)  EDGE(1, 5, 0)   EDGE(1, 4, 3)   EDGE(1, 6, 3)
    EDGE(2, 4, 0)   EDGE(3, 6, 0)   EDGE(4, 14, 3)  EDGE(5, 7, 2)
    EDGE(5, 8, 2)   EDGE(7, 10, 0)  EDGE(7, 15, 2)  EDGE(8, 11, 0)
    EDGE(8, 20, 2)  EDGE(9, 11, 1)  EDGE(9, 12, 0)  EDGE(11, 19, 1)
    EDGE(13, 14, 0) EDGE(14, 15, 0) EDGE(16, 17, 0) EDGE(18, 19, 0)
    EDGE(20, 21, 0) EDGE(20, 27, 2) EDGE(13, 30, 4) EDGE(30, 35, 4)
    EDGE(35, 31, 4) EDGE(30, 33, 0) EDGE(31, 28, 0) EDGE(31, 34, 0)
    EDGE(28, 32, 3) EDGE(32, 29, 0) EDGE(16, 23, 1) EDGE(23, 25, 1)
    EDGE(22, 25, 0) EDGE(23, 26, 0) EDGE(26, 29, 2) EDGE(29, 27, 2)
    EDGE(27, 24, 0)
    return r;
}

// plan_path: writes a shortest path start -> end into path[] and its length into *count.
// dist[n] = shortest distance from node n to 'end' (255 = not reached yet);
// dist needs 37 bytes (dist[0] is a flag) and must not overlap path[].
// Distances are found by relaxing every line until nothing improves, then the
// path is walked forwards: always step to a neighbour that is one line closer.
static void plan_path(uint8_t start, uint8_t end, uint8_t *dist,
                      uint8_t *path, uint8_t *count) {
    uint32_t k, cur, nxt, n;
    for (k = 0; k < 37; k++) dist[k] = 255;
    dist[end] = 0;
    do {
        dist[0] = 0;
        scan_edges(dist, 0);
    } while (dist[0]);
    cur = start;
    path[0] = cur;
    n = 1;
    while (cur != end && n < 20) {
        nxt = scan_edges(dist, cur);
        if (nxt == 0) break;                 // safety: cannot happen on a connected arena
        cur = nxt;
        path[n++] = cur;
    }
    *count = n;
}

// ##############################################

// main function
int main(int argc, char const *argv[]) {

    #ifdef __linux__

        if (argc < 4) {
            _put_str("usage: ./Path_Planner_Dec <current_node> <next_node> <is_encrypted>\n");
            _put_str("       current_node     : where the bot is, e.g. 35 (the start box)\n");
            _put_str("       is_encrypted = 0 : next_node is a node number, e.g. 7\n");
            _put_str("       is_encrypted = 1 : next_node is the encrypted code, 16 hex digits\n");
            return 1;
        }
        uint8_t  CURRENT_NODE        = atoi(argv[1]);
        uint8_t  IS_ENCRYPTED        = atoi(argv[3]);
        uint8_t  NEXT_NODE           = 0;
        uint32_t ENCRYPTED_HI        = 0;
        uint32_t ENCRYPTED_LO        = 0;
        if (IS_ENCRYPTED) {
            if (!read_block(argv[2], &ENCRYPTED_HI, &ENCRYPTED_LO)) {
                _put_str("with is_encrypted = 1, next_node must be exactly 16 hex digits\n");
                return 1;
            }
        }
        else {
            NEXT_NODE = atoi(argv[2]);
        }
        uint8_t MESSAGE_0           = 0;
        uint8_t MESSAGE_1           = 0;
        uint8_t MESSAGE_2           = 0;
        uint8_t MESSAGE_3           = 0;
        uint8_t MESSAGE_4           = 0;
        uint8_t NODE_POINT          = 0;
        uint8_t CPU_DONE            = 0;

    #else
        // Address value of variables are updated for RISC-V Implementation
        // inputs: 0x02000000 .. 0x0200000F
        #define ENCRYPTED_HI        (* (volatile uint32_t * ) 0x02000000)
        #define ENCRYPTED_LO        (* (volatile uint32_t * ) 0x02000004)
        #define IS_ENCRYPTED        (* (volatile uint8_t  * ) 0x02000008)
        #define NEXT_NODE           (* (volatile uint8_t  * ) 0x0200000c)
        #define CURRENT_NODE        (* (volatile uint8_t  * ) 0x0200000d)
        // outputs: 0x02000010 .. 0x0200001F
        #define MESSAGE_0           (* (volatile uint8_t  * ) 0x02000010)
        #define MESSAGE_1           (* (volatile uint8_t  * ) 0x02000011)
        #define MESSAGE_2           (* (volatile uint8_t  * ) 0x02000012)
        #define MESSAGE_3           (* (volatile uint8_t  * ) 0x02000013)
        #define MESSAGE_4           (* (volatile uint8_t  * ) 0x02000014)
        #define NODE_POINT          (* (volatile uint8_t  * ) 0x02000018)
        #define CPU_DONE            (* (volatile uint8_t  * ) 0x0200001c)

    #endif

    // read once here: for the next run, the program may write IS_ENCRYPTED = 0
    uint8_t is_encrypted = IS_ENCRYPTED;

    // the message: bytes 1..5 of the decrypted block (0x00 = no character)
    uint8_t message[5] = { 0, 0, 0, 0, 0 };

    // array to store the planned path
    uint8_t path_planned[40];
    // index to keep track of the path_planned array
    uint8_t idx = 0;

    uint8_t start_point = CURRENT_NODE;   // where the bot is
    uint8_t end_point   = 0;              // where the bot goes

    // ############# Add your code here #############

    // set path_planned[] and idx, message[] when is_encrypted = 1, and the
    // inputs for the next run (see Outputs at the top of this file)

    // work: 20 bytes of working memory, used first for the decryption (key
    // register work[0..2], decrypted block work[3..4]) and afterwards for the
    // planned route (at most 13 nodes). route is the same memory as bytes.
    #ifdef __linux__
        uint32_t work[5];
    #else
        uint32_t *work = (uint32_t *) 0x02000020;    // working memory starts at 0x02000020
    #endif
    uint8_t *route = (uint8_t *) work;

    // the shortest-distance table (37 bytes) borrows path_planned[] while the
    // route is planned; the route is copied into path_planned[] at the end
    uint8_t i_copy, done_flag = 1, next_pickup = 0;

    end_point = NEXT_NODE;                           // plain node number case
    if (is_encrypted) {
        work[3] = ENCRYPTED_HI;                      // copied: the input is never written
        work[4] = ENCRYPTED_LO;
        present_decrypt(&work[3], work, PRESENT_KEY_HI, PRESENT_KEY_MID, PRESENT_KEY_LO);
        message[0] = (work[3] >> 16) & 0xFF;         // bytes 1..5
        message[1] = (work[3] >> 8) & 0xFF;
        message[2] = work[3] & 0xFF;
        message[3] = (work[4] >> 24) & 0xFF;
        message[4] = (work[4] >> 16) & 0xFF;
        done_flag   = (work[3] >> 24) & 1;           // byte 0
        next_pickup = (work[4] >> 8) & 0xFF;         // byte 6: next pick-up node
        end_point   = work[4] & 0xFF;                // byte 7: drop node
    }

    plan_path(start_point, end_point, path_planned, route, &idx);
    for (i_copy = 0; i_copy < idx; i_copy++) path_planned[i_copy] = route[i_copy];

    // done flag = 0: write the inputs for the next run
    if (is_encrypted && done_flag == 0) {
        IS_ENCRYPTED = 0;
        CURRENT_NODE = end_point;                    // the drop node
        NEXT_NODE    = next_pickup;
    }

    // ##############################################

    // the message bytes are written into data memory (encrypted block only).
    if (is_encrypted) {
        MESSAGE_0 = message[0];
        MESSAGE_1 = message[1];
        MESSAGE_2 = message[2];
        MESSAGE_3 = message[3];
        MESSAGE_4 = message[4];
    }
    // the node values are written into data memory sequentially.
    for (int i = 0; i < idx; ++i) {
        NODE_POINT = path_planned[i];
    }
    // Path Planning Computation Done Flag
    CPU_DONE = 1;

    #ifdef __linux__    // for host pc: the output test.sh reads (see "Output (PC)" at the top)

        if (is_encrypted) {
            _put_str("Message : ");
            for (int i = 0; i < 5; ++i) {
                if (message[i]) _put_byte(message[i]);
            }
            _put_byte('\n');
        }
        for (int i = 0; i < idx; ++i) {
            _put_value(path_planned[i]);
        }
        if (is_encrypted) {
            if (IS_ENCRYPTED == 0) {            // the inputs written for the next run
                _put_str("Next current_node : ");
                _put_value(CURRENT_NODE);
                _put_str("Next next_node : ");
                _put_value(NEXT_NODE);
            }
            else {
                _put_str("Done\n");
            }
        }

    #endif

    return 0;
}