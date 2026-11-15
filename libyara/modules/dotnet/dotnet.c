/*
Copyright (c) 2015. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <yara/dotnet.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/pe.h>
#include <yara/pe_utils.h>
#include <yara/simple_str.h>
#include <yara/strutils.h>
#include <yara/unaligned.h>

#define MODULE_NAME dotnet

static uint32_t max_rows(int count, ...)
{
  va_list ap;
  uint32_t biggest;
  uint32_t x;

  if (count == 0)
    return 0;

  va_start(ap, count);
  biggest = va_arg(ap, uint32_t);

  for (int i = 1; i < count; i++)
  {
    x = va_arg(ap, uint32_t);
    biggest = (x > biggest) ? x : biggest;
  }

  va_end(ap);
  return biggest;
}

static uint32_t read_u32(const uint8_t** data)
{
  uint32_t result = yr_le32toh(yr_unaligned_u32(*data));
  *data += sizeof(uint32_t);
  return result;
}

static uint16_t read_u16(const uint8_t** data)
{
  uint16_t result = yr_le16toh(yr_unaligned_u16(*data));
  *data += sizeof(uint16_t);
  return result;
}

static uint8_t read_u8(const uint8_t** data)
{
  uint8_t result = **data;
  *data += sizeof(uint8_t);
  return result;
}

static uint32_t read_index(const uint8_t** data, uint8_t len)
{
  if (len == 2)
    return read_u16(data);
  else
    return read_u32(data);
}

// ECMA-335 II.25.4.2, CorILMethod. The low two bits identify the method body
// format, while the remaining bits carry format-specific information.
#define DOTNET_METHOD_FORMAT_MASK  0x03
#define DOTNET_METHOD_TINY_FORMAT  0x02
#define DOTNET_METHOD_FAT_FORMAT   0x03
#define DOTNET_METHOD_MORE_SECTS   0x08
#define DOTNET_METHOD_INIT_LOCALS  0x10

// ECMA-335 II.25.4.6, CorILMethodSect.
#define DOTNET_METHOD_SECT_EH_TABLE   0x01
#define DOTNET_METHOD_SECT_KIND_MASK  0x3f
#define DOTNET_METHOD_SECT_FAT_FORMAT 0x40

#define DOTNET_MAX_IL_INSTRUCTIONS 100000
#define DOTNET_MAX_EH_CLAUSES      10000
#define DOTNET_MAX_PATTERN_TOKENS  128

typedef enum
{
  DOTNET_OPERAND_NONE = 0,
  DOTNET_OPERAND_I1,
  DOTNET_OPERAND_I4,
  DOTNET_OPERAND_I8,
  DOTNET_OPERAND_R4,
  DOTNET_OPERAND_R8,
  DOTNET_OPERAND_METHOD,
  DOTNET_OPERAND_FIELD,
  DOTNET_OPERAND_TYPE,
  DOTNET_OPERAND_STRING,
  DOTNET_OPERAND_TOKEN,
  DOTNET_OPERAND_SIG,
  DOTNET_OPERAND_VAR,
  DOTNET_OPERAND_SHORT_VAR,
  DOTNET_OPERAND_BRANCH,
  DOTNET_OPERAND_SHORT_BRANCH,
  DOTNET_OPERAND_SWITCH
} DOTNET_OPERAND_KIND;

typedef struct
{
  uint16_t opcode;
  const char* name;
  DOTNET_OPERAND_KIND operand_type;
} DOTNET_OPCODE;

// Complete CIL opcode table (ECMA-335 III). Two-byte opcodes are represented
// with the 0xFE prefix, e.g. ceq is 0xFE01. The table is sorted by opcode.
static const DOTNET_OPCODE dotnet_opcodes[] = {
    {0x0000, "nop", DOTNET_OPERAND_NONE},
    {0x0001, "break", DOTNET_OPERAND_NONE},
    {0x0002, "ldarg.0", DOTNET_OPERAND_NONE},
    {0x0003, "ldarg.1", DOTNET_OPERAND_NONE},
    {0x0004, "ldarg.2", DOTNET_OPERAND_NONE},
    {0x0005, "ldarg.3", DOTNET_OPERAND_NONE},
    {0x0006, "ldloc.0", DOTNET_OPERAND_NONE},
    {0x0007, "ldloc.1", DOTNET_OPERAND_NONE},
    {0x0008, "ldloc.2", DOTNET_OPERAND_NONE},
    {0x0009, "ldloc.3", DOTNET_OPERAND_NONE},
    {0x000A, "stloc.0", DOTNET_OPERAND_NONE},
    {0x000B, "stloc.1", DOTNET_OPERAND_NONE},
    {0x000C, "stloc.2", DOTNET_OPERAND_NONE},
    {0x000D, "stloc.3", DOTNET_OPERAND_NONE},
    {0x000E, "ldarg.s", DOTNET_OPERAND_SHORT_VAR},
    {0x000F, "ldarga.s", DOTNET_OPERAND_SHORT_VAR},
    {0x0010, "starg.s", DOTNET_OPERAND_SHORT_VAR},
    {0x0011, "ldloc.s", DOTNET_OPERAND_SHORT_VAR},
    {0x0012, "ldloca.s", DOTNET_OPERAND_SHORT_VAR},
    {0x0013, "stloc.s", DOTNET_OPERAND_SHORT_VAR},
    {0x0014, "ldnull", DOTNET_OPERAND_NONE},
    {0x0015, "ldc.i4.m1", DOTNET_OPERAND_NONE},
    {0x0016, "ldc.i4.0", DOTNET_OPERAND_NONE},
    {0x0017, "ldc.i4.1", DOTNET_OPERAND_NONE},
    {0x0018, "ldc.i4.2", DOTNET_OPERAND_NONE},
    {0x0019, "ldc.i4.3", DOTNET_OPERAND_NONE},
    {0x001A, "ldc.i4.4", DOTNET_OPERAND_NONE},
    {0x001B, "ldc.i4.5", DOTNET_OPERAND_NONE},
    {0x001C, "ldc.i4.6", DOTNET_OPERAND_NONE},
    {0x001D, "ldc.i4.7", DOTNET_OPERAND_NONE},
    {0x001E, "ldc.i4.8", DOTNET_OPERAND_NONE},
    {0x001F, "ldc.i4.s", DOTNET_OPERAND_I1},
    {0x0020, "ldc.i4", DOTNET_OPERAND_I4},
    {0x0021, "ldc.i8", DOTNET_OPERAND_I8},
    {0x0022, "ldc.r4", DOTNET_OPERAND_R4},
    {0x0023, "ldc.r8", DOTNET_OPERAND_R8},
    {0x0025, "dup", DOTNET_OPERAND_NONE},
    {0x0026, "pop", DOTNET_OPERAND_NONE},
    {0x0027, "jmp", DOTNET_OPERAND_METHOD},
    {0x0028, "call", DOTNET_OPERAND_METHOD},
    {0x0029, "calli", DOTNET_OPERAND_SIG},
    {0x002A, "ret", DOTNET_OPERAND_NONE},
    {0x002B, "br.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x002C, "brfalse.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x002D, "brtrue.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x002E, "beq.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x002F, "bge.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0030, "bgt.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0031, "ble.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0032, "blt.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0033, "bne.un.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0034, "bge.un.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0035, "bgt.un.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0036, "ble.un.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0037, "blt.un.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x0038, "br", DOTNET_OPERAND_BRANCH},
    {0x0039, "brfalse", DOTNET_OPERAND_BRANCH},
    {0x003A, "brtrue", DOTNET_OPERAND_BRANCH},
    {0x003B, "beq", DOTNET_OPERAND_BRANCH},
    {0x003C, "bge", DOTNET_OPERAND_BRANCH},
    {0x003D, "bgt", DOTNET_OPERAND_BRANCH},
    {0x003E, "ble", DOTNET_OPERAND_BRANCH},
    {0x003F, "blt", DOTNET_OPERAND_BRANCH},
    {0x0040, "bne.un", DOTNET_OPERAND_BRANCH},
    {0x0041, "bge.un", DOTNET_OPERAND_BRANCH},
    {0x0042, "bgt.un", DOTNET_OPERAND_BRANCH},
    {0x0043, "ble.un", DOTNET_OPERAND_BRANCH},
    {0x0044, "blt.un", DOTNET_OPERAND_BRANCH},
    {0x0045, "switch", DOTNET_OPERAND_SWITCH},
    {0x0046, "ldind.i1", DOTNET_OPERAND_NONE},
    {0x0047, "ldind.u1", DOTNET_OPERAND_NONE},
    {0x0048, "ldind.i2", DOTNET_OPERAND_NONE},
    {0x0049, "ldind.u2", DOTNET_OPERAND_NONE},
    {0x004A, "ldind.i4", DOTNET_OPERAND_NONE},
    {0x004B, "ldind.u4", DOTNET_OPERAND_NONE},
    {0x004C, "ldind.i8", DOTNET_OPERAND_NONE},
    {0x004D, "ldind.i", DOTNET_OPERAND_NONE},
    {0x004E, "ldind.r4", DOTNET_OPERAND_NONE},
    {0x004F, "ldind.r8", DOTNET_OPERAND_NONE},
    {0x0050, "ldind.ref", DOTNET_OPERAND_NONE},
    {0x0051, "stind.ref", DOTNET_OPERAND_NONE},
    {0x0052, "stind.i1", DOTNET_OPERAND_NONE},
    {0x0053, "stind.i2", DOTNET_OPERAND_NONE},
    {0x0054, "stind.i4", DOTNET_OPERAND_NONE},
    {0x0055, "stind.i8", DOTNET_OPERAND_NONE},
    {0x0056, "stind.r4", DOTNET_OPERAND_NONE},
    {0x0057, "stind.r8", DOTNET_OPERAND_NONE},
    {0x0058, "add", DOTNET_OPERAND_NONE},
    {0x0059, "sub", DOTNET_OPERAND_NONE},
    {0x005A, "mul", DOTNET_OPERAND_NONE},
    {0x005B, "div", DOTNET_OPERAND_NONE},
    {0x005C, "div.un", DOTNET_OPERAND_NONE},
    {0x005D, "rem", DOTNET_OPERAND_NONE},
    {0x005E, "rem.un", DOTNET_OPERAND_NONE},
    {0x005F, "and", DOTNET_OPERAND_NONE},
    {0x0060, "or", DOTNET_OPERAND_NONE},
    {0x0061, "xor", DOTNET_OPERAND_NONE},
    {0x0062, "shl", DOTNET_OPERAND_NONE},
    {0x0063, "shr", DOTNET_OPERAND_NONE},
    {0x0064, "shr.un", DOTNET_OPERAND_NONE},
    {0x0065, "neg", DOTNET_OPERAND_NONE},
    {0x0066, "not", DOTNET_OPERAND_NONE},
    {0x0067, "conv.i1", DOTNET_OPERAND_NONE},
    {0x0068, "conv.i2", DOTNET_OPERAND_NONE},
    {0x0069, "conv.i4", DOTNET_OPERAND_NONE},
    {0x006A, "conv.i8", DOTNET_OPERAND_NONE},
    {0x006B, "conv.r4", DOTNET_OPERAND_NONE},
    {0x006C, "conv.r8", DOTNET_OPERAND_NONE},
    {0x006D, "conv.u4", DOTNET_OPERAND_NONE},
    {0x006E, "conv.u8", DOTNET_OPERAND_NONE},
    {0x006F, "callvirt", DOTNET_OPERAND_METHOD},
    {0x0070, "cpobj", DOTNET_OPERAND_TYPE},
    {0x0071, "ldobj", DOTNET_OPERAND_TYPE},
    {0x0072, "ldstr", DOTNET_OPERAND_STRING},
    {0x0073, "newobj", DOTNET_OPERAND_METHOD},
    {0x0074, "castclass", DOTNET_OPERAND_TYPE},
    {0x0075, "isinst", DOTNET_OPERAND_TYPE},
    {0x0076, "conv.r.un", DOTNET_OPERAND_NONE},
    {0x0079, "unbox", DOTNET_OPERAND_TYPE},
    {0x007A, "throw", DOTNET_OPERAND_NONE},
    {0x007B, "ldfld", DOTNET_OPERAND_FIELD},
    {0x007C, "ldflda", DOTNET_OPERAND_FIELD},
    {0x007D, "stfld", DOTNET_OPERAND_FIELD},
    {0x007E, "ldsfld", DOTNET_OPERAND_FIELD},
    {0x007F, "ldsflda", DOTNET_OPERAND_FIELD},
    {0x0080, "stsfld", DOTNET_OPERAND_FIELD},
    {0x0081, "stobj", DOTNET_OPERAND_TYPE},
    {0x0082, "conv.ovf.i1.un", DOTNET_OPERAND_NONE},
    {0x0083, "conv.ovf.i2.un", DOTNET_OPERAND_NONE},
    {0x0084, "conv.ovf.i4.un", DOTNET_OPERAND_NONE},
    {0x0085, "conv.ovf.i8.un", DOTNET_OPERAND_NONE},
    {0x0086, "conv.ovf.u1.un", DOTNET_OPERAND_NONE},
    {0x0087, "conv.ovf.u2.un", DOTNET_OPERAND_NONE},
    {0x0088, "conv.ovf.u4.un", DOTNET_OPERAND_NONE},
    {0x0089, "conv.ovf.u8.un", DOTNET_OPERAND_NONE},
    {0x008A, "conv.ovf.i.un", DOTNET_OPERAND_NONE},
    {0x008B, "conv.ovf.u.un", DOTNET_OPERAND_NONE},
    {0x008C, "box", DOTNET_OPERAND_TYPE},
    {0x008D, "newarr", DOTNET_OPERAND_TYPE},
    {0x008E, "ldlen", DOTNET_OPERAND_NONE},
    {0x008F, "ldelema", DOTNET_OPERAND_TYPE},
    {0x0090, "ldelem.i1", DOTNET_OPERAND_NONE},
    {0x0091, "ldelem.u1", DOTNET_OPERAND_NONE},
    {0x0092, "ldelem.i2", DOTNET_OPERAND_NONE},
    {0x0093, "ldelem.u2", DOTNET_OPERAND_NONE},
    {0x0094, "ldelem.i4", DOTNET_OPERAND_NONE},
    {0x0095, "ldelem.u4", DOTNET_OPERAND_NONE},
    {0x0096, "ldelem.i8", DOTNET_OPERAND_NONE},
    {0x0097, "ldelem.i", DOTNET_OPERAND_NONE},
    {0x0098, "ldelem.r4", DOTNET_OPERAND_NONE},
    {0x0099, "ldelem.r8", DOTNET_OPERAND_NONE},
    {0x009A, "ldelem.ref", DOTNET_OPERAND_NONE},
    {0x009B, "stelem.i", DOTNET_OPERAND_NONE},
    {0x009C, "stelem.i1", DOTNET_OPERAND_NONE},
    {0x009D, "stelem.i2", DOTNET_OPERAND_NONE},
    {0x009E, "stelem.i4", DOTNET_OPERAND_NONE},
    {0x009F, "stelem.i8", DOTNET_OPERAND_NONE},
    {0x00A0, "stelem.r4", DOTNET_OPERAND_NONE},
    {0x00A1, "stelem.r8", DOTNET_OPERAND_NONE},
    {0x00A2, "stelem.ref", DOTNET_OPERAND_NONE},
    {0x00A3, "ldelem", DOTNET_OPERAND_TYPE},
    {0x00A4, "stelem", DOTNET_OPERAND_TYPE},
    {0x00A5, "unbox.any", DOTNET_OPERAND_TYPE},
    {0x00B3, "conv.ovf.i1", DOTNET_OPERAND_NONE},
    {0x00B4, "conv.ovf.u1", DOTNET_OPERAND_NONE},
    {0x00B5, "conv.ovf.i2", DOTNET_OPERAND_NONE},
    {0x00B6, "conv.ovf.u2", DOTNET_OPERAND_NONE},
    {0x00B7, "conv.ovf.i4", DOTNET_OPERAND_NONE},
    {0x00B8, "conv.ovf.u4", DOTNET_OPERAND_NONE},
    {0x00B9, "conv.ovf.i8", DOTNET_OPERAND_NONE},
    {0x00BA, "conv.ovf.u8", DOTNET_OPERAND_NONE},
    {0x00C2, "refanyval", DOTNET_OPERAND_TYPE},
    {0x00C3, "ckfinite", DOTNET_OPERAND_NONE},
    {0x00C6, "mkrefany", DOTNET_OPERAND_TYPE},
    {0x00D0, "ldtoken", DOTNET_OPERAND_TOKEN},
    {0x00D1, "conv.u2", DOTNET_OPERAND_NONE},
    {0x00D2, "conv.u1", DOTNET_OPERAND_NONE},
    {0x00D3, "conv.i", DOTNET_OPERAND_NONE},
    {0x00D4, "conv.ovf.i", DOTNET_OPERAND_NONE},
    {0x00D5, "conv.ovf.u", DOTNET_OPERAND_NONE},
    {0x00D6, "add.ovf", DOTNET_OPERAND_NONE},
    {0x00D7, "add.ovf.un", DOTNET_OPERAND_NONE},
    {0x00D8, "mul.ovf", DOTNET_OPERAND_NONE},
    {0x00D9, "mul.ovf.un", DOTNET_OPERAND_NONE},
    {0x00DA, "sub.ovf", DOTNET_OPERAND_NONE},
    {0x00DB, "sub.ovf.un", DOTNET_OPERAND_NONE},
    {0x00DC, "endfinally", DOTNET_OPERAND_NONE},
    {0x00DD, "leave", DOTNET_OPERAND_BRANCH},
    {0x00DE, "leave.s", DOTNET_OPERAND_SHORT_BRANCH},
    {0x00DF, "stind.i", DOTNET_OPERAND_NONE},
    {0x00E0, "conv.u", DOTNET_OPERAND_NONE},
    {0x00F8, "prefix7", DOTNET_OPERAND_NONE},
    {0x00F9, "prefix6", DOTNET_OPERAND_NONE},
    {0x00FA, "prefix5", DOTNET_OPERAND_NONE},
    {0x00FB, "prefix4", DOTNET_OPERAND_NONE},
    {0x00FC, "prefix3", DOTNET_OPERAND_NONE},
    {0x00FD, "prefix2", DOTNET_OPERAND_NONE},
    {0x00FE, "prefix1", DOTNET_OPERAND_NONE},
    {0x00FF, "prefixref", DOTNET_OPERAND_NONE},
    {0xFE00, "arglist", DOTNET_OPERAND_NONE},
    {0xFE01, "ceq", DOTNET_OPERAND_NONE},
    {0xFE02, "cgt", DOTNET_OPERAND_NONE},
    {0xFE03, "cgt.un", DOTNET_OPERAND_NONE},
    {0xFE04, "clt", DOTNET_OPERAND_NONE},
    {0xFE05, "clt.un", DOTNET_OPERAND_NONE},
    {0xFE06, "ldftn", DOTNET_OPERAND_METHOD},
    {0xFE07, "ldvirtftn", DOTNET_OPERAND_METHOD},
    {0xFE09, "ldarg", DOTNET_OPERAND_VAR},
    {0xFE0A, "ldarga", DOTNET_OPERAND_VAR},
    {0xFE0B, "starg", DOTNET_OPERAND_VAR},
    {0xFE0C, "ldloc", DOTNET_OPERAND_VAR},
    {0xFE0D, "ldloca", DOTNET_OPERAND_VAR},
    {0xFE0E, "stloc", DOTNET_OPERAND_VAR},
    {0xFE0F, "localloc", DOTNET_OPERAND_NONE},
    {0xFE11, "endfilter", DOTNET_OPERAND_NONE},
    {0xFE12, "unaligned.", DOTNET_OPERAND_I1},
    {0xFE13, "volatile.", DOTNET_OPERAND_NONE},
    {0xFE14, "tail.", DOTNET_OPERAND_NONE},
    {0xFE15, "initobj", DOTNET_OPERAND_TYPE},
    {0xFE16, "constrained.", DOTNET_OPERAND_TYPE},
    {0xFE17, "cpblk", DOTNET_OPERAND_NONE},
    {0xFE18, "initblk", DOTNET_OPERAND_NONE},
    {0xFE19, "no.", DOTNET_OPERAND_I1},
    {0xFE1A, "rethrow", DOTNET_OPERAND_NONE},
    {0xFE1C, "sizeof", DOTNET_OPERAND_TYPE},
    {0xFE1D, "refanytype", DOTNET_OPERAND_NONE},
    {0xFE1E, "readonly.", DOTNET_OPERAND_NONE},
};

static const DOTNET_OPCODE* dotnet_lookup_opcode(uint16_t opcode)
{
  size_t low = 0;
  size_t high = sizeof(dotnet_opcodes) / sizeof(dotnet_opcodes[0]);

  while (low < high)
  {
    size_t mid = low + (high - low) / 2;

    if (dotnet_opcodes[mid].opcode == opcode)
      return &dotnet_opcodes[mid];
    else if (dotnet_opcodes[mid].opcode < opcode)
      low = mid + 1;
    else
      high = mid;
  }

  return NULL;
}

static uint32_t dotnet_operand_size(const DOTNET_OPCODE* opcode)
{
  switch (opcode->operand_type)
  {
  case DOTNET_OPERAND_NONE:
    return 0;
  case DOTNET_OPERAND_I1:
  case DOTNET_OPERAND_SHORT_VAR:
  case DOTNET_OPERAND_SHORT_BRANCH:
    return 1;
  case DOTNET_OPERAND_VAR:
    return 2;
  case DOTNET_OPERAND_I4:
  case DOTNET_OPERAND_R4:
  case DOTNET_OPERAND_METHOD:
  case DOTNET_OPERAND_FIELD:
  case DOTNET_OPERAND_TYPE:
  case DOTNET_OPERAND_STRING:
  case DOTNET_OPERAND_TOKEN:
  case DOTNET_OPERAND_SIG:
  case DOTNET_OPERAND_BRANCH:
    return 4;
  case DOTNET_OPERAND_I8:
  case DOTNET_OPERAND_R8:
    return 8;
  case DOTNET_OPERAND_SWITCH:
    return 0;
  }

  return 0;
}

// Returns valid offset within the table or NULL
const uint8_t* get_table_offset(const TABLE_INFO* tbl, uint32_t index)
{
  // Indexes to .NET tables are based from 1
  if (index < 1 || index > tbl->RowCount)
    return NULL;

  return tbl->Offset + tbl->RowSize * (index - 1);
}

// Given an offset into a #US or #Blob stream, parse the entry at that position.
// The offset is relative to the start of the PE file.
// if size > 0 then it's valid and readable blob
BLOB_PARSE_RESULT dotnet_parse_blob_entry(PE* pe, const uint8_t* offset)
{
  BLOB_PARSE_RESULT result = {.size = 0, .length = 0};

  // Blob size is encoded in the first 1, 2 or 4 bytes of the blob.
  //
  // If the high bit is not set the length is encoded in one byte.
  //
  // If the high 2 bits are 10 (base 2) then the length is encoded in
  // the rest of the bits and the next byte.
  //
  // If the high 3 bits are 110 (base 2) then the length is encoded
  // in the rest of the bits and the next 3 bytes.
  //
  // See ECMA-335 II.24.2.4 for details.

  // Make sure we have at least one byte.

  if (!fits_in_pe(pe, offset, 1))
    return result;

  if ((*offset & 0x80) == 0x00)
  {
    result.length = (uint32_t) (*offset);
    result.size = 1;
  }
  else if ((*offset & 0xC0) == 0x80)
  {
    // Make sure we have one more byte.
    if (!fits_in_pe(pe, offset, 2))
      return result;

    // Shift remaining 6 bits left by 8 and OR in the remaining byte.
    result.length = ((*offset & 0x3F) << 8) | *(offset + 1);
    result.size = 2;
  }
  else if (offset + 4 < pe->data + pe->data_size && (*offset & 0xE0) == 0xC0)
  {
    // Make sure we have 3 more bytes.
    if (!fits_in_pe(pe, offset, 4))
      return result;

    result.length = ((*offset & 0x1F) << 24) | (*(offset + 1) << 16) |
                    (*(offset + 2) << 8) | *(offset + 3);
    result.size = 4;
  }
  else
  {
    // Return a 0 size as an error.
    return result;
  }

  // Check if the length is actually readable
  if (!fits_in_pe(pe, offset, result.size + result.length))
  {
    result.size = 0;
    return result;
  }

  return result;
}

char* pe_get_dotnet_string(
    PE* pe,
    const uint8_t* heap_offset,
    uint32_t heap_size,
    uint32_t string_index)
{
  size_t remaining;

  char* start;
  char* eos;

  // Start of string must be within boundary
  if (!(heap_offset + string_index >= pe->data &&
        heap_offset + string_index < pe->data + pe->data_size &&
        string_index < heap_size))
    return NULL;

  // Calculate how much until end of boundary, don't scan past that.
  remaining = (pe->data + pe->data_size) - (heap_offset + string_index);

  // Search for a NULL terminator from start of string, up to remaining.
  start = (char*) (heap_offset + string_index);
  eos = (char*) memmem((void*) start, remaining, "\0", 1);

  // If no NULL terminator was found or the string is too large, return NULL.
  if (eos == NULL || eos - start > 1024)
    return NULL;

  return start;
}

static bool is_nested(uint32_t flags)
{
  // ECMA 335 II.22.37
  // Whether a type is nested can be determined by the value of its
  // Flags.Visibility sub-field – it shall be one of the set
  // { NestedPublic, NestedPrivate, NestedFamily, NestedAssembly,
  // NestedFamANDAssem, NestedFamORAssem }

  switch (flags & TYPE_ATTR_VISIBILITY_MASK)
  {
  case TYPE_ATTR_NESTED_PRIVATE:
  case TYPE_ATTR_NESTED_PUBLIC:
  case TYPE_ATTR_NESTED_FAMILY:
  case TYPE_ATTR_NESTED_ASSEMBLY:
  case TYPE_ATTR_NESTED_FAM_AND_ASSEM:
  case TYPE_ATTR_NESTED_FAM_OR_ASSEM:
    return true;
  default:
    return false;
  }
}

// ECMA 335 II.23.1.15 Flags for types [TypeAttribute]
static const char* get_type_visibility(uint32_t flags)
{
  switch (flags & TYPE_ATTR_VISIBILITY_MASK)
  {
  case TYPE_ATTR_NESTED_PRIVATE:
    return "private";
  case TYPE_ATTR_PUBLIC:
  case TYPE_ATTR_NESTED_PUBLIC:
    return "public";
  case TYPE_ATTR_NESTED_FAMILY:
    return "protected";
  case TYPE_ATTR_NOT_PUBLIC:
  case TYPE_ATTR_NESTED_ASSEMBLY:
    return "internal";
  case TYPE_ATTR_NESTED_FAM_AND_ASSEM:
    return "private protected";
  case TYPE_ATTR_NESTED_FAM_OR_ASSEM:
    return "protected internal";
  default:
    return "private";
  }
}

// ECMA 335 II.23.1.10 Flags for methods [MethodAttributes]
static const char* get_method_visibility(uint32_t flags)
{
  switch (flags & METHOD_ATTR_ACCESS_MASK)
  {
  case METHOD_ATTR_PRIVATE:
    return "private";
  case METHOD_ATTR_FAM_AND_ASSEM:
    return "private protected";
  case METHOD_ATTR_ASSEM:
    return "internal";
  case METHOD_ATTR_FAMILY:
    return "protected";
  case METHOD_ATTR_FAM_OR_ASSEM:
    return "protected internal";
  case METHOD_ATTR_PUBLIC:
    return "public";
  default:
    return "private";
  }
}

// ECMA 335 II.23.1.15 Flags for types [TypeAttribute]
static const char* get_typedef_type(uint32_t flags)
{
  switch (flags & TYPE_ATTR_CLASS_SEMANTIC_MASK)
  {
  case TYPE_ATTR_CLASS:
    return "class";
  case TYPE_ATTR_INTERFACE:
    return "interface";
  default:
    return NULL;
  }
}

// returns allocated string <namespace>.<name>, must be freed
static char* create_full_name(const char* name, const char* namespace)
{
  if (!name || !strlen(name))
    return namespace ? yr_strdup(namespace) : NULL;

  // No namespace -> return name only
  if (!namespace || !strlen(namespace))
  {
    // fix generic names
    char* name_copy = yr_strdup(name);
    char* end = strchr(name_copy, '`');
    if (end)
      *end = 0;
    return name_copy;
  }

  size_t name_len = strlen(name);
  size_t namespace_len = strlen(namespace);

  // <namespace>.<name>
  char* full_name = yr_malloc(namespace_len + 1 + name_len + 1);

  memcpy(full_name, namespace, namespace_len);
  full_name[namespace_len] = '.';
  memcpy(full_name + namespace_len + 1, name, name_len + 1);

  // fix generic names
  char* end = strchr(full_name, '`');
  if (end)
    *end = 0;

  return full_name;
}

static bool read_typedef(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    TYPEDEF_ROW* result)
{
  uint32_t row_size = ctx->tables->typedef_.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    uint8_t ext_size = 2;
    uint32_t row_count = max_rows(
        3,
        ctx->tables->typedef_.RowCount,
        ctx->tables->typeref.RowCount,
        ctx->tables->typespec.RowCount);

    if (row_count > (0xFFFF >> 0x02))
      ext_size = 4;

    result->Flags = read_u32(&data);
    result->Name = read_index(&data, ctx->index_sizes->string);
    result->Namespace = read_index(&data, ctx->index_sizes->string);
    result->Extends = read_index(&data, ext_size);
    result->Field = read_index(&data, ctx->index_sizes->field);
    result->Method = read_index(&data, ctx->index_sizes->methoddef);

    return true;
  }

  return false;
}

static bool read_typeref(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    TYPEREF_ROW* result)
{
  uint32_t row_size = ctx->tables->typeref.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    uint8_t res_size = 2;
    uint32_t row_count = max_rows(
        4,
        ctx->tables->module.RowCount,
        ctx->tables->moduleref.RowCount,
        ctx->tables->assemblyref.RowCount,
        ctx->tables->typeref.RowCount);

    if (row_count > (0xFFFF >> 0x02))
      res_size = 4;

    result->ResolutionScope = read_index(&data, res_size);
    result->Name = read_index(&data, ctx->index_sizes->string);
    result->Namespace = read_index(&data, ctx->index_sizes->string);

    return true;
  }

  return false;
}

static bool read_interfaceimpl(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    INTERFACEIMPL_ROW* result)
{
  uint32_t row_size = ctx->tables->intefaceimpl.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    uint32_t interface_size = 2;
    uint32_t row_count = max_rows(
        3,
        ctx->tables->typedef_.RowCount,
        ctx->tables->typeref.RowCount,
        ctx->tables->typespec.RowCount);

    if (row_count > (0xFFFF >> 0x02))
      interface_size = 4;

    result->Class = read_index(&data, ctx->index_sizes->typedef_);
    result->Interface = read_index(&data, interface_size);

    return true;
  }

  return false;
}

static bool read_methoddef(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    METHODDEF_ROW* result)
{
  uint32_t row_size = ctx->tables->methoddef.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    result->Rva = read_u32(&data);
    result->ImplFlags = read_u16(&data);
    result->Flags = read_u16(&data);
    result->Name = read_index(&data, ctx->index_sizes->string);
    result->Signature = read_index(&data, ctx->index_sizes->blob);
    result->ParamList = read_index(&data, ctx->index_sizes->param);
    return true;
  }

  return false;
}

static bool read_param(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    PARAM_ROW* result)
{
  uint32_t row_size = ctx->tables->param.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    result->Flags = read_u16(&data);
    result->Sequence = read_u16(&data);
    result->Name = read_index(&data, ctx->index_sizes->string);
    return true;
  }

  return false;
}

static bool read_genericparam(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    GENERICPARAM_ROW* result)
{
  uint32_t row_size = ctx->tables->genericparam.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    uint32_t owner_idx_size = 2;
    uint32_t row_count = max_rows(
        2, ctx->tables->typedef_.RowCount, ctx->tables->methoddef.RowCount);

    if (row_count > (0xFFFF >> 0x01))
      owner_idx_size = 4;

    result->Number = read_u16(&data);
    result->Flags = read_u16(&data);
    result->Owner = read_index(&data, owner_idx_size);
    result->Name = read_index(&data, ctx->index_sizes->string);
    return true;
  }

  return false;
}

static bool read_typespec(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    TYPESPEC_ROW* result)
{
  uint32_t row_size = ctx->tables->typespec.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    result->Signature = read_index(&data, ctx->index_sizes->blob);
    return true;
  }

  return false;
}

static bool read_nestedclass(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    NESTEDCLASS_ROW* result)
{
  uint32_t row_size = ctx->tables->nestedclass.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    result->NestedClass = read_index(&data, ctx->index_sizes->typedef_);
    result->EnclosingClass = read_index(&data, ctx->index_sizes->typedef_);
    return true;
  }

  return false;
}

// ECMA-335 II.23.2 blob heap uses variable length encoding of integers
static uint32_t read_blob_unsigned(const uint8_t** data, uint32_t* len)
{
  if (*len < 1)
    return 0;

  // first byte is enough to decode the length
  // without worrying about endiannity
  // Compressed integers use big-endian order
  uint8_t first_byte = *(*data);

  // If the value lies between 0 (0x00) and 127 (0x7F), inclusive, encode as a
  // one-byte integer (bit 7 is clear, value held in bits 6 through 0)
  if (!(first_byte & 0x80))
  {
    *data += sizeof(uint8_t);
    *len -= sizeof(uint8_t);
    return first_byte;
  }

  if (*len < 2)
    return 0;

  // If the value lies between 2^8 (0x80) and 2^14 – 1 (0x3FFF), inclusive,
  // encode as a 2-byte integer with bit 15 set, bit 14 clear (value held in
  // bits 13 through 0)
  if ((first_byte & 0xC0) == 0x80)
  {
    uint32_t result = yr_be16toh(yr_unaligned_u16(*data));
    *data += sizeof(uint16_t);
    *len -= sizeof(uint16_t);
    // value is in lower 14 bits
    return result & 0x3FFF;
  }

  if (*len < 4)
    return 0;

  // Otherwise, encode as a 4-byte integer, with bit 31 set, bit 30 set,
  // bit 29 clear (value held in bits 28 through 0)
  if ((first_byte & 0xE0) == 0xC0)
  {
    uint32_t result = yr_be32toh(yr_unaligned_u32(*data));
    *data += sizeof(uint32_t);
    *len -= sizeof(uint32_t);
    // Uses last 29 bits for the result
    return result & 0x1FFFFFFF;
  }

  return 0;
}

// ECMA-335 II.23.2 blob heap uses variable length encoding of integers
// Probably wouldn't work on non 2's complement arches?
static int32_t read_blob_signed(const uint8_t** data, uint32_t* len)
{
  // Compressed integers use big-endian order!
  if (*len < 1)
    return 0;

  // first byte is enough to decode the length
  // without worrying about endiannity
  int8_t first_byte = *(*data);

  // Encode as a one-byte integer, bit 7 clear, rotated value in bits 6
  // through 0, giving 0x01 (-2^6) to 0x7E (2^6-1).
  if (!(first_byte & 0x80))
  {
    int8_t tmp = first_byte >> 1;
    // sign extension in case of negative number
    if (first_byte & 0x1)
      tmp |= 0xC0;

    *data += sizeof(uint8_t);
    *len -= sizeof(uint8_t);

    return (int32_t) tmp;
  }

  if (*len < 2)
    return 0;

  // Encode as a two-byte integer: bit 15 set, bit 14 clear, rotated value
  // in bits 13 through 0, giving 0x8001 (-2^13) to 0xBFFE (2^13-1).
  if ((first_byte & 0xC0) == 0x80)
  {
    uint16_t tmp1 = yr_be16toh(yr_unaligned_u16(*data));
    // shift and leave top 2 bits clear
    int16_t tmp2 = (tmp1 >> 1) & 0x3FFF;
    // sign extension in case of negative number
    if (tmp1 & 0x1)
      tmp2 |= 0xE000;

    *data += sizeof(uint16_t);
    *len -= sizeof(uint16_t);

    return (int32_t) tmp2;
  }

  if (*len < 4)
    return 0;

  // Encode as a four-byte integer: bit 31 set, 30 set, bit 29 clear,
  // rotated value in bits 28 through 0, giving 0xC0000001 (-2^28) to
  // 0xDFFFFFFE (2^28-1).
  if ((first_byte & 0xE0) == 0xC0)
  {
    uint32_t tmp1 = yr_be32toh(yr_unaligned_u32(*data));
    // shift and leave top 3 bits clear
    int32_t tmp2 = (tmp1 >> 1) & 0x1FFFFFFF;
    // sign extension in case of negative number
    if (tmp1 & 0x1)
      tmp2 |= 0xF0000000;

    *data += sizeof(uint32_t);
    *len -= sizeof(uint32_t);

    return (int32_t) tmp2;
  }

  return 0;
}

// Forward declarations
static char* parse_signature_type(
    const CLASS_CONTEXT* ctx,
    const uint8_t** data,
    uint32_t* len,
    GENERIC_PARAMETERS* class_gen_params,
    GENERIC_PARAMETERS* method_gen_params,
    uint32_t depth);

static char* parse_enclosing_types(
    const CLASS_CONTEXT* ctx,
    uint32_t nested_idx,
    uint32_t depth);

static char* get_type_def_or_ref_fullname(
    const CLASS_CONTEXT* ctx,
    uint32_t coded_index,
    GENERIC_PARAMETERS* class_gen_params,
    GENERIC_PARAMETERS* method_gen_params,
    uint32_t depth)  // against loops
{
  // first 2 bits define table, index starts with third bit
  uint32_t index = coded_index >> 2;
  if (!index)
    return NULL;

  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  uint8_t table = coded_index & 0x3;
  if (table == 0)  // TypeDef
  {
    const uint8_t* data = get_table_offset(&ctx->tables->typedef_, index);
    if (!data)
      return NULL;

    TYPEDEF_ROW def_row;
    bool result = read_typedef(ctx, data, &def_row);
    if (result)
    {
      const char* name = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, def_row.Name);
      const char* namespace = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, def_row.Namespace);

      char* result = NULL;
      // Type might be nested, try to find correct namespace
      if (is_nested(def_row.Flags))
      {
        char* nested_namespace = parse_enclosing_types(ctx, index, 1);
        char* tmp = create_full_name(namespace, nested_namespace);
        result = create_full_name(name, tmp);
        yr_free(nested_namespace);
        yr_free(tmp);
      }
      else
        result = create_full_name(name, namespace);

      return result;
    }
  }
  else if (table == 1)  // TypeRef
  {
    const uint8_t* data = get_table_offset(&ctx->tables->typeref, index);
    if (!data)
      return NULL;

    TYPEREF_ROW ref_row;
    bool result = read_typeref(ctx, data, &ref_row);
    if (result)
    {
      const char* name = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, ref_row.Name);
      const char* namespace = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, ref_row.Namespace);

      return create_full_name(name, namespace);
    }
  }
  else if (table == 2)  // TypeSpec
  {
    const uint8_t* data = get_table_offset(&ctx->tables->typespec, index);
    if (!data)
      return NULL;

    TYPESPEC_ROW spec_row;
    bool result = read_typespec(ctx, data, &spec_row);
    if (result && spec_row.Signature < ctx->blob_size)
    {
      const uint8_t* sig_data = ctx->blob_heap + spec_row.Signature;

      // Read the blob entry with the data
      BLOB_PARSE_RESULT blob_res = dotnet_parse_blob_entry(ctx->pe, sig_data);
      sig_data += blob_res.size;
      uint32_t sig_len = blob_res.length;

      // Valid blob
      if (blob_res.size)
        return parse_signature_type(
            ctx, &sig_data, &sig_len, class_gen_params, NULL, depth);
    }
  }
  return NULL;
}

static char* parse_signature_type(
    const CLASS_CONTEXT* ctx,
    const uint8_t** data,
    uint32_t* len,
    GENERIC_PARAMETERS* class_gen_params,
    GENERIC_PARAMETERS* method_gen_params,
    uint32_t depth  // against loops
)
{
  // If at least first type fits and we are not too nested
  if (*len < 1 || !fits_in_pe(ctx->pe, *data, 1) || depth > MAX_TYPE_DEPTH)
    return NULL;

  bool class = false;
  uint32_t coded_index, index;
  char* tmp = NULL;
  char* ret_type = NULL;

  uint8_t type = read_u8(data);
  *len -= 1;

  switch (type)
  {
  case TYPE_VOID:
    ret_type = "void";
    break;

  case TYPE_BOOL:
    ret_type = "bool";
    break;

  case TYPE_CHAR:
    ret_type = "char";
    break;

  case TYPE_I1:
    ret_type = "sbyte";
    break;

  case TYPE_U1:
    ret_type = "byte";
    break;

  case TYPE_I2:
    ret_type = "short";
    break;

  case TYPE_U2:
    ret_type = "ushort";
    break;

  case TYPE_I4:
    ret_type = "int";
    break;

  case TYPE_U4:
    ret_type = "uint";
    break;

  case TYPE_I8:
    ret_type = "long";
    break;

  case TYPE_U8:
    ret_type = "ulong";
    break;

  case TYPE_R4:
    ret_type = "float";
    break;

  case TYPE_R8:
    ret_type = "double";
    break;

  case TYPE_STRING:
    ret_type = "string";
    break;

  case TYPE_TYPEDREF:
    ret_type = "TypedReference";
    break;

  case TYPE_I:
    ret_type = "IntPtr";
    break;

  case TYPE_U:
    ret_type = "UIntPtr";
    break;

  case TYPE_PTR:  // Ptr followed by type
    tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
    if (tmp)
    {
      SIMPLE_STR* ss = sstr_new(NULL);
      if (!ss)
      {
        yr_free(tmp);
        break;
      }
      bool res = sstr_appendf(ss, "Ptr<%s>", tmp);
      if (res)
        ret_type = sstr_move(ss);

      yr_free(tmp);
      sstr_free(ss);
      return ret_type;
    }
    break;

  case TYPE_BYREF:
    // ByRef followed by type
    tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
    if (tmp)
    {
      SIMPLE_STR* ss = sstr_new(NULL);
      if (!ss)
      {
        yr_free(tmp);
        break;
      }
      bool res = sstr_appendf(ss, "ref %s", tmp);
      if (res)
        ret_type = sstr_move(ss);

      yr_free(tmp);
      sstr_free(ss);
      return ret_type;
    }
    break;

  case TYPE_VALUETYPE:  // ValueType
  case TYPE_CLASS:      // Class
    // followed by TypeDefOrRefOrSpecEncoded index
    coded_index = read_blob_unsigned(data, len);
    return get_type_def_or_ref_fullname(
        ctx, coded_index, class_gen_params, method_gen_params, depth + 1);
    break;

  case TYPE_VAR:   // Generic class var
  case TYPE_MVAR:  // Generic method var
    index = read_blob_unsigned(data, len);
    class = type == TYPE_VAR;
    // return class generic var or method generic var
    if (class && class_gen_params && index < class_gen_params->len)
      ret_type = class_gen_params->names[index];
    else if (!class && method_gen_params && index < method_gen_params->len)
      ret_type = method_gen_params->names[index];
    break;

  case TYPE_ARRAY:
  {
    // Array -> Type -> Rank -> NumSizes -> Size -> NumLobound -> LoBound
    char* tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
    if (!tmp)
      break;

    int32_t* sizes = NULL;
    int32_t* lo_bounds = NULL;

    // Read number of dimensions
    uint32_t rank = read_blob_unsigned(data, len);
    if (!rank || rank > MAX_ARRAY_RANK)
      goto cleanup;

    // Read number of specified sizes
    uint32_t num_sizes = read_blob_unsigned(data, len);
    if (num_sizes > rank)
      goto cleanup;
    sizes = yr_malloc(sizeof(int64_t) * num_sizes);
    if (!sizes)
      goto cleanup;

    for (uint32_t i = 0; i < num_sizes; ++i)
    {
      sizes[i] = (int64_t) read_blob_unsigned(data, len);
    }

    // Read number of specified lower bounds
    uint32_t num_lowbounds = read_blob_unsigned(data, len);
    lo_bounds = yr_malloc(sizeof(int32_t) * num_lowbounds);
    if (!lo_bounds || num_lowbounds > rank)
      goto cleanup;

    for (uint32_t i = 0; i < num_lowbounds; ++i)
    {
      lo_bounds[i] = read_blob_signed(data, len);

      // Adjust higher bound according to lower bound
      if (num_sizes > i && lo_bounds[i] != 0)
        sizes[i] += lo_bounds[i] - 1;
    }

    // Build the resulting array type
    SIMPLE_STR* ss = sstr_new(NULL);
    if (!ss)
      goto cleanup;

    sstr_appendf(ss, "%s[", tmp);

    for (uint32_t i = 0; i < rank; ++i)
    {
      if (num_sizes > i || num_lowbounds > i)
      {
        if (num_lowbounds > i && lo_bounds[i] != 0)
          sstr_appendf(ss, "%d...", lo_bounds[i]);
        if (num_sizes > i)
          sstr_appendf(ss, "%d", sizes[i]);
      }
      if (i + 1 != rank)
        sstr_appendf(ss, ",");
    }
    bool res = sstr_appendf(ss, "]");
    if (res)
      ret_type = sstr_move(ss);

    yr_free(sizes);
    yr_free(lo_bounds);
    yr_free(tmp);
    sstr_free(ss);
    return ret_type;

  cleanup:
    yr_free(sizes);
    yr_free(lo_bounds);
    yr_free(tmp);
  }
  break;

  case TYPE_GENERICINST:
  {
    tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);

    if (!tmp)
      break;

    uint32_t gen_count = read_blob_unsigned(data, len);

    // Sanity check for corrupted files
    if (gen_count > MAX_GEN_PARAM_COUNT)
    {
      yr_free(tmp);
      break;
    }

    SIMPLE_STR* ss = sstr_new(NULL);
    if (!ss)
    {
      yr_free(tmp);
      break;
    }
    sstr_appendf(ss, "%s<", tmp);
    yr_free(tmp);

    for (int i = 0; i < gen_count; i++)
    {
      char* param_type = parse_signature_type(
          ctx, data, len, class_gen_params, method_gen_params, depth + 1);

      if (param_type != NULL)
      {
        if (i > 0)
          sstr_appendf(ss, ",");

        sstr_appendf(ss, "%s", param_type);
        yr_free(param_type);
      }
    }
    bool res = sstr_appendf(ss, ">");
    if (res)
      ret_type = sstr_move(ss);

    sstr_free(ss);
    return ret_type;
  }
  break;

  case TYPE_FNPTR:
    if (*len > 0)
    {  // Flags -> ParamCount -> RetType -> Param -> Sentinel ->Param
      // Skip flags
      (*data)++;
      (*len)--;

      uint32_t param_count = read_blob_unsigned(data, len);

      // Sanity check for corrupted files
      if (param_count > MAX_PARAM_COUNT)
      {
        yr_free(tmp);
        break;
      }

      tmp = parse_signature_type(
          ctx, data, len, class_gen_params, method_gen_params, depth + 1);

      if (!tmp)
        break;

      SIMPLE_STR* ss = sstr_new(NULL);
      if (!ss)
      {
        yr_free(tmp);
        break;
      }

      sstr_appendf(ss, "FnPtr<%s(", tmp);
      yr_free(tmp);

      for (int i = 0; i < param_count; i++)
      {
        char* param_type = parse_signature_type(
            ctx, data, len, class_gen_params, method_gen_params, depth + 1);

        if (param_type != NULL)
        {
          if (i > 0)
            sstr_appendf(ss, ", ");

          sstr_appendf(ss, "%s", param_type);
          yr_free(param_type);
        }
      }

      if (sstr_appendf(ss, ")>"))
        ret_type = sstr_move(ss);

      sstr_free(ss);
      return ret_type;
    }
    break;

  case TYPE_OBJECT:
    ret_type = "object";
    break;

  case TYPE_SZARRAY:
    // Single dimensional array followed by type
    tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
    if (tmp)
    {
      SIMPLE_STR* ss = sstr_newf("%s[]", tmp);
      if (ss)
        ret_type = sstr_move(ss);

      yr_free(tmp);
      sstr_free(ss);
      return ret_type;
    }
    break;

  case TYPE_CMOD_REQD:  // Req modifier
  case TYPE_CMOD_OPT:   // Opt modifier
  {
    // What is point of these
    // Right now ignore them...
    read_blob_unsigned(data, len);
    return parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
  }
  break;

  default:
    break;
  }

  if (ret_type)
    return yr_strdup(ret_type);
  else
    return NULL;
}

static void parse_type_parents(
    const CLASS_CONTEXT* ctx,
    uint32_t extends,
    uint32_t type_idx,
    uint32_t out_idx,  // Class idx in output array
    GENERIC_PARAMETERS* class_gen_params)
{
  // Find the parent class
  char* parent = get_type_def_or_ref_fullname(
      ctx, extends, class_gen_params, NULL, 0);

  uint32_t base_type_idx = 0;
  if (parent)
  {
    yr_set_string(
        parent,
        ctx->pe->object,
        "classes[%i].base_types[%i]",
        out_idx,
        base_type_idx++);

    yr_free(parent);
  }

  // linear search for every interface that the class implements
  for (uint32_t idx = 0; idx < ctx->tables->intefaceimpl.RowCount; ++idx)
  {
    const uint8_t* data = get_table_offset(&ctx->tables->intefaceimpl, idx + 1);
    if (!data)
      break;

    INTERFACEIMPL_ROW row = {0};
    bool result = read_interfaceimpl(ctx, data, &row);
    if (!result)
      continue;

    // We found the inherited interface
    if (row.Class == type_idx)
    {
      char* inteface = get_type_def_or_ref_fullname(
          ctx, row.Interface, class_gen_params, NULL, 0);
      if (inteface)
      {
        yr_set_string(
            inteface,
            ctx->pe->object,
            "classes[%i].base_types[%i]",
            out_idx,
            base_type_idx++);

        yr_free(inteface);
      }
    }
  }
  yr_set_integer(
      base_type_idx,
      ctx->pe->object,
      "classes[%i].number_of_base_types",
      out_idx);
}

// Returns true if all parameters were correctly parsed
static bool parse_method_params(
    const CLASS_CONTEXT* ctx,
    uint32_t param_list,
    uint32_t method_idx,  // used for output
    uint32_t class_idx,
    uint32_t param_count,
    const uint8_t* sig_data,
    uint32_t sig_len,
    GENERIC_PARAMETERS* class_gen_params,
    GENERIC_PARAMETERS* method_gen_params)
{
  if (!param_list)  // NULL
    return true;

  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  // Array to hold all the possible parameters
  PARAMETERS* params = yr_calloc(param_count, sizeof(PARAMETERS));

  if (params == NULL && param_count > 0)
    return false;

  for (uint32_t idx = 0; idx < param_count; ++idx)
  {
    const uint8_t* data = get_table_offset(
        &ctx->tables->param, param_list + idx);

    char* name = NULL;
    bool alloc = false;  // Flag if name needs freeing

    if (data)  // We need param table mostly just for the param name
    {
      PARAM_ROW row = {0};
      bool result = read_param(ctx, data, &row);

      if (!result)
      {  // Cleanup and return
        for (uint32_t j = 0; j < idx; ++j)
        {
          if (params[j].alloc)
            yr_free(params[j].name);

          yr_free(params[j].type);
        }
        yr_free(params);
        return false;
      }

      name = pe_get_dotnet_string(ctx->pe, str_heap, str_size, row.Name);
    }
    else  // We can reconstruct their type from the signature
          // and give them default name
    {
      alloc = true;
      SIMPLE_STR* ss = sstr_newf("P_%lu", idx);
      if (ss)
      {
        name = sstr_move(ss);
        sstr_free(ss);
      }
    }

    char* type = parse_signature_type(
        ctx, &sig_data, &sig_len, class_gen_params, method_gen_params, 0);

    params[idx].alloc = alloc;
    params[idx].name = name;
    params[idx].type = type;

    if (!type)  // If any param fails, whole parsing is aborted
    {
      for (uint32_t j = 0; j <= idx; ++j)
      {
        if (params[j].alloc)
          yr_free(params[j].name);

        yr_free(params[j].type);
      }
      yr_free(params);
      return false;
    }
  }

  // If we got all of them correctly, write to output and cleanup
  YR_OBJECT* out_obj = ctx->pe->object;
  yr_set_integer(
      param_count,
      out_obj,
      "classes[%i].methods[%i].number_of_parameters",
      class_idx,
      method_idx);

  for (uint32_t i = 0; i < param_count; ++i)
  {
    yr_set_string(
        params[i].name,
        out_obj,
        "classes[%i].methods[%i].parameters[%i].name",
        class_idx,
        method_idx,
        i);
    yr_set_string(
        params[i].type,
        out_obj,
        "classes[%i].methods[%i].parameters[%i].type",
        class_idx,
        method_idx,
        i);
    if (params[i].alloc)
      yr_free(params[i].name);

    yr_free(params[i].type);
  }

  yr_free(params);
  return true;
}

// Walks GenericParam table, finds all generic params for the MethodDef or
// TypeDef entry and allocates buffer with the Generic param names into result
static void parse_generic_params(
    const CLASS_CONTEXT* ctx,
    bool method,  // true means MethodDef, false TypeDef index
    uint32_t gen_idx,
    GENERIC_PARAMETERS* result)
{
  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  result->names = NULL;
  result->len = 0;

  // Walk the GenericParam table to find GenParameters of the class/method
  for (uint32_t idx = 0; idx < ctx->tables->genericparam.RowCount; ++idx)
  {
    const uint8_t* data = get_table_offset(&ctx->tables->genericparam, idx + 1);
    if (!data)
      goto cleanup;

    GENERICPARAM_ROW row = {0};
    bool read_result = read_genericparam(ctx, data, &row);
    if (!read_result)
      continue;

    // TypeOrMethodDef coded index
    uint8_t table = row.Owner & 0x1;
    // 0 == TypeDef 1 == MethodDef
    // Check if it's generic param of the type we want
    if (table == method && (row.Owner >> 1) == gen_idx)
    {
      char* name = pe_get_dotnet_string(ctx->pe, str_heap, str_size, row.Name);
      // name must be valid string
      if (!name || !*name)  // ERROR
        goto cleanup;

      result->len += 1;
      char** tmp = yr_realloc(result->names, result->len * sizeof(char*));
      if (!tmp)
        goto cleanup;

      // Update the collection
      result->names = tmp;
      result->names[result->len - 1] = name;
    }
  }
  return;

cleanup:
  yr_free(result->names);
  result->names = NULL;
  result->len = 0;
}

static bool dotnet_fits_at(PE* pe, int64_t offset, size_t size)
{
  return offset >= 0 && (uint64_t) offset <= pe->data_size &&
         fits_in_pe(pe, pe->data + offset, size);
}

static void dotnet_set_eh_handler(
    YR_OBJECT* out_obj,
    uint32_t class_idx,
    uint32_t method_idx,
    uint32_t handler_idx,
    int64_t clause_offset,
    uint32_t flags,
    uint32_t try_offset,
    uint32_t try_length,
    uint32_t handler_offset,
    uint32_t handler_length,
    uint32_t class_token,
    uint32_t filter_offset)
{
  const char* type;

  switch (flags & 0x7)
  {
  case 0:
    type = "catch";
    break;
  case 1:
    type = "filter";
    break;
  case 2:
    type = "finally";
    break;
  case 4:
    type = "fault";
    break;
  default:
    type = "unknown";
    break;
  }

#define SET_EH_INTEGER(field, value)                                          \
  do                                                                          \
  {                                                                           \
    yr_set_integer(                                                           \
        value,                                                                \
        out_obj,                                                              \
        "classes[%i].methods[%i].exception_handlers[%i]." field,              \
        class_idx,                                                            \
        method_idx,                                                           \
        handler_idx);                                                         \
    yr_set_integer(                                                           \
        value,                                                                \
        out_obj,                                                              \
        "classes[%i].methods[%i].exception_regions[%i]." field,               \
        class_idx,                                                            \
        method_idx,                                                           \
        handler_idx);                                                         \
  } while (0)

#define SET_EH_STRING(field, value)                                           \
  do                                                                          \
  {                                                                           \
    yr_set_string(                                                            \
        value,                                                                \
        out_obj,                                                              \
        "classes[%i].methods[%i].exception_handlers[%i]." field,              \
        class_idx,                                                            \
        method_idx,                                                           \
        handler_idx);                                                         \
    yr_set_string(                                                            \
        value,                                                                \
        out_obj,                                                              \
        "classes[%i].methods[%i].exception_regions[%i]." field,               \
        class_idx,                                                            \
        method_idx,                                                           \
        handler_idx);                                                         \
  } while (0)

  SET_EH_INTEGER("offset", clause_offset);
  SET_EH_INTEGER("flags", flags);
  SET_EH_INTEGER("try_offset", try_offset);
  SET_EH_INTEGER("try_start", try_offset);
  SET_EH_INTEGER("try_length", try_length);
  SET_EH_INTEGER("try_end", (int64_t) try_offset + try_length);
  SET_EH_INTEGER("handler_offset", handler_offset);
  SET_EH_INTEGER("handler_start", handler_offset);
  SET_EH_INTEGER("handler_length", handler_length);
  SET_EH_INTEGER("handler_end", (int64_t) handler_offset + handler_length);
  SET_EH_INTEGER("class_token", class_token);
  SET_EH_INTEGER("catch_type", class_token);
  SET_EH_INTEGER("catch_type_token", class_token);
  SET_EH_INTEGER("filter_offset", filter_offset);
  SET_EH_INTEGER("filter_start", filter_offset);
  SET_EH_INTEGER("exception_type", flags);
  SET_EH_STRING("type", type);
  SET_EH_STRING("handler_type", type);

#undef SET_EH_INTEGER
#undef SET_EH_STRING
}

static uint32_t dotnet_parse_exception_sections(
    PE* pe,
    YR_OBJECT* out_obj,
    uint32_t class_idx,
    uint32_t method_idx,
    int64_t body_offset,
    uint32_t header_size,
    uint32_t code_size,
    uint32_t flags)
{
  uint32_t handler_count = 0;
  uint32_t section_count = 0;
  int64_t section_offset;
  int64_t body_end = body_offset + header_size + code_size;

  if (!(flags & DOTNET_METHOD_MORE_SECTS))
    return 0;

  section_offset = body_offset + ((header_size + code_size + 3) & ~3u);

  while (section_count++ < 16 && dotnet_fits_at(pe, section_offset, 4))
  {
    const uint8_t* section = pe->data + section_offset;
    uint8_t kind = section[0];
    uint32_t data_size;
    bool fat = (kind & DOTNET_METHOD_SECT_FAT_FORMAT) != 0;

    if (fat)
      data_size = (uint32_t) section[1] | ((uint32_t) section[2] << 8) |
                  ((uint32_t) section[3] << 16);
    else
      data_size = section[1];

    if (!dotnet_fits_at(pe, section_offset + 4, data_size))
      break;

    if ((kind & DOTNET_METHOD_SECT_KIND_MASK) ==
        DOTNET_METHOD_SECT_EH_TABLE)
    {
      uint32_t clause_size = fat ? 24 : 12;
      uint32_t clauses = data_size / clause_size;
      const uint8_t* clause_data = section + 4;

      for (uint32_t i = 0; i < clauses && i < DOTNET_MAX_EH_CLAUSES; i++)
      {
        const uint8_t* clause = clause_data + i * clause_size;
        uint32_t clause_flags;
        uint32_t try_offset;
        uint32_t try_length;
        uint32_t handler_offset;
        uint32_t handler_length;
        uint32_t class_token = 0;
        uint32_t filter_offset = 0;

        if (fat)
        {
          clause_flags = yr_le32toh(yr_unaligned_u32(clause));
          try_offset = yr_le32toh(yr_unaligned_u32(clause + 4));
          try_length = yr_le32toh(yr_unaligned_u32(clause + 8));
          handler_offset = yr_le32toh(yr_unaligned_u32(clause + 12));
          handler_length = yr_le32toh(yr_unaligned_u32(clause + 16));

          if ((clause_flags & 0x7) == 0)
            class_token = yr_le32toh(yr_unaligned_u32(clause + 20));
          else if ((clause_flags & 0x7) == 1)
            filter_offset = yr_le32toh(yr_unaligned_u32(clause + 20));
        }
        else
        {
          clause_flags = yr_le16toh(yr_unaligned_u16(clause));
          try_offset = yr_le16toh(yr_unaligned_u16(clause + 2));
          try_length = clause[4];
          handler_offset = yr_le16toh(yr_unaligned_u16(clause + 5));
          handler_length = clause[7];

          if ((clause_flags & 0x7) == 0)
            class_token = yr_le32toh(yr_unaligned_u32(clause + 8));
          else if ((clause_flags & 0x7) == 1)
            filter_offset = yr_le32toh(yr_unaligned_u32(clause + 8));
        }

        dotnet_set_eh_handler(
            out_obj,
            class_idx,
            method_idx,
            handler_count,
            section_offset + 4 + i * clause_size,
            clause_flags,
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            class_token,
            filter_offset);

        handler_count++;
      }
    }

    body_end = section_offset + 4 + data_size;

    if (!(kind & 0x80))
      break;

    section_offset = (body_end + 3) & ~3;
  }

  yr_set_integer(
      body_end - body_offset,
      out_obj,
      "classes[%i].methods[%i].body_size",
      class_idx,
      method_idx);
  yr_set_integer(
      body_end - body_offset,
      out_obj,
      "classes[%i].methods[%i].size",
      class_idx,
      method_idx);

  return handler_count;
}

static void dotnet_parse_method_body(
    PE* pe,
    uint32_t method_rva,
    uint32_t class_idx,
    uint32_t method_idx)
{
  YR_OBJECT* out_obj = pe->object;
  int64_t body_offset = -1;
  uint32_t header_size = 0;
  uint32_t code_size = 0;
  uint32_t flags = 0;
  uint32_t max_stack = 0;
  uint32_t local_var_sig_tok = 0;
  bool tiny = false;
  bool fat = false;

  yr_set_integer(
      method_rva, out_obj, "classes[%i].methods[%i].rva", class_idx, method_idx);
  yr_set_integer(0, out_obj, "classes[%i].methods[%i].has_body", class_idx, method_idx);
  yr_set_integer(0, out_obj, "classes[%i].methods[%i].is_tiny", class_idx, method_idx);
  yr_set_integer(0, out_obj, "classes[%i].methods[%i].is_fat", class_idx, method_idx);
  yr_set_integer(
      0, out_obj, "classes[%i].methods[%i].number_of_instructions", class_idx, method_idx);
  yr_set_integer(
      0, out_obj, "classes[%i].methods[%i].instruction_count", class_idx, method_idx);
  yr_set_integer(
      0, out_obj, "classes[%i].methods[%i].number_of_opcodes", class_idx, method_idx);
  yr_set_integer(
      0,
      out_obj,
      "classes[%i].methods[%i].number_of_exception_handlers",
      class_idx,
      method_idx);
  yr_set_integer(
      0,
      out_obj,
      "classes[%i].methods[%i].exception_handler_count",
      class_idx,
      method_idx);
  yr_set_integer(
      0,
      out_obj,
      "classes[%i].methods[%i].number_of_exception_regions",
      class_idx,
      method_idx);
  yr_set_string("none", out_obj, "classes[%i].methods[%i].format", class_idx, method_idx);

  if (method_rva == 0)
    return;

  body_offset = pe_rva_to_offset(pe, method_rva);

  if (!dotnet_fits_at(pe, body_offset, 1))
    return;

  const uint8_t* body = pe->data + body_offset;

  if ((body[0] & DOTNET_METHOD_FORMAT_MASK) == DOTNET_METHOD_TINY_FORMAT)
  {
    tiny = true;
    flags = DOTNET_METHOD_TINY_FORMAT;
    header_size = 1;
    code_size = body[0] >> 2;
    max_stack = 8;
  }
  else if ((body[0] & DOTNET_METHOD_FORMAT_MASK) == DOTNET_METHOD_FAT_FORMAT)
  {
    fat = true;

    if (!dotnet_fits_at(pe, body_offset, 12))
      return;

    uint16_t flags_and_size = yr_le16toh(yr_unaligned_u16(body));
    header_size = (flags_and_size >> 12) * 4;
    flags = flags_and_size & 0x0fff;

    if (header_size < 12 || !dotnet_fits_at(pe, body_offset, header_size))
      return;

    max_stack = yr_le16toh(yr_unaligned_u16(body + 2));
    code_size = yr_le32toh(yr_unaligned_u32(body + 4));
    local_var_sig_tok = yr_le32toh(yr_unaligned_u32(body + 8));
  }
  else
  {
    return;
  }

  if (!dotnet_fits_at(pe, body_offset + header_size, code_size))
    return;

  yr_set_integer(1, out_obj, "classes[%i].methods[%i].has_body", class_idx, method_idx);
  yr_set_integer(tiny, out_obj, "classes[%i].methods[%i].is_tiny", class_idx, method_idx);
  yr_set_integer(fat, out_obj, "classes[%i].methods[%i].is_fat", class_idx, method_idx);
  const char* format = tiny ? "tiny" : "fat";
  yr_set_string(format, out_obj, "classes[%i].methods[%i].format", class_idx, method_idx);
  yr_set_integer(body_offset, out_obj, "classes[%i].methods[%i].offset", class_idx, method_idx);
  yr_set_integer(header_size, out_obj, "classes[%i].methods[%i].header_size", class_idx, method_idx);
  yr_set_integer(
      body_offset + header_size,
      out_obj,
      "classes[%i].methods[%i].code_offset",
      class_idx,
      method_idx);
  yr_set_integer(code_size, out_obj, "classes[%i].methods[%i].code_size", class_idx, method_idx);
  yr_set_integer(max_stack, out_obj, "classes[%i].methods[%i].max_stack", class_idx, method_idx);
  yr_set_integer(
      local_var_sig_tok,
      out_obj,
      "classes[%i].methods[%i].local_var_sig_tok",
      class_idx,
      method_idx);
  yr_set_integer(
      local_var_sig_tok,
      out_obj,
      "classes[%i].methods[%i].local_var_sig_token",
      class_idx,
      method_idx);
  yr_set_integer(flags, out_obj, "classes[%i].methods[%i].flags", class_idx, method_idx);
  yr_set_integer(
      (flags & DOTNET_METHOD_INIT_LOCALS) != 0,
      out_obj,
      "classes[%i].methods[%i].init_locals",
      class_idx,
      method_idx);
  yr_set_integer(
      header_size + code_size,
      out_obj,
      "classes[%i].methods[%i].body_size",
      class_idx,
      method_idx);
  yr_set_integer(
      header_size + code_size,
      out_obj,
      "classes[%i].methods[%i].size",
      class_idx,
      method_idx);

  const uint8_t* code = body + header_size;
  uint32_t il_offset = 0;
  uint32_t instruction_count = 0;

  while (il_offset < code_size &&
         instruction_count < DOTNET_MAX_IL_INSTRUCTIONS)
  {
    uint32_t remaining = code_size - il_offset;
    uint8_t first = code[il_offset];
    uint16_t opcode_value = first;
    uint32_t opcode_size = 1;

    if (first == 0xFE)
    {
      if (remaining < 2)
        break;

      opcode_value = 0xFE00 | code[il_offset + 1];
      opcode_size = 2;
    }

    const DOTNET_OPCODE* opcode = dotnet_lookup_opcode(opcode_value);

    if (opcode == NULL)
      break;

    uint32_t operand_size = dotnet_operand_size(opcode);
    uint32_t switch_count = 0;
    int64_t operand = 0;

    if (opcode->operand_type == DOTNET_OPERAND_SWITCH)
    {
      if (remaining < opcode_size + 4)
        break;

      switch_count = yr_le32toh(
          yr_unaligned_u32(code + il_offset + opcode_size));

      if (switch_count > (remaining - opcode_size - 4) / 4)
        break;

      operand_size = 4 + switch_count * 4;
      operand = switch_count;
    }

    uint32_t instruction_size = opcode_size + operand_size;

    if (instruction_size > remaining)
      break;

    const uint8_t* operand_data = code + il_offset + opcode_size;

    switch (opcode->operand_type)
    {
    case DOTNET_OPERAND_I1:
    case DOTNET_OPERAND_SHORT_VAR:
      operand = *operand_data;
      break;
    case DOTNET_OPERAND_SHORT_BRANCH:
      operand = (int8_t) *operand_data;
      break;
    case DOTNET_OPERAND_I4:
    case DOTNET_OPERAND_R4:
    case DOTNET_OPERAND_METHOD:
    case DOTNET_OPERAND_FIELD:
    case DOTNET_OPERAND_TYPE:
    case DOTNET_OPERAND_STRING:
    case DOTNET_OPERAND_TOKEN:
    case DOTNET_OPERAND_SIG:
      operand = yr_le32toh(yr_unaligned_u32(operand_data));
      break;
    case DOTNET_OPERAND_BRANCH:
      operand = (int32_t) yr_le32toh(yr_unaligned_u32(operand_data));
      break;
    case DOTNET_OPERAND_VAR:
      operand = yr_le16toh(yr_unaligned_u16(operand_data));
      break;
    case DOTNET_OPERAND_I8:
    case DOTNET_OPERAND_R8:
      operand = (int64_t) yr_le64toh(yr_unaligned_u64(operand_data));
      break;
    default:
      break;
    }

    yr_set_integer(
        il_offset,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].offset",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        il_offset,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].il_offset",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        body_offset + header_size + il_offset,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].file_offset",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        method_rva + header_size + il_offset,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].rva",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        method_rva + header_size + il_offset,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].address",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        opcode_value,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].opcode",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        opcode_size,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].opcode_size",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_string(
        opcode->name,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].opcode_name",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_string(
        opcode->name,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].mnemonic",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_string(
        opcode->name,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].name",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        operand,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].operand",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        operand_size,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].operand_size",
        class_idx,
        method_idx,
        instruction_count);
    yr_set_integer(
        instruction_size,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].size",
        class_idx,
        method_idx,
        instruction_count);

    if (opcode->operand_type == DOTNET_OPERAND_BRANCH ||
        opcode->operand_type == DOTNET_OPERAND_SHORT_BRANCH)
    {
      yr_set_integer(
          (int64_t) il_offset + instruction_size + operand,
          out_obj,
          "classes[%i].methods[%i].instructions[%i].branch_target",
          class_idx,
          method_idx,
          instruction_count);
    }

    yr_set_integer(
        switch_count,
        out_obj,
        "classes[%i].methods[%i].instructions[%i].number_of_switch_targets",
        class_idx,
        method_idx,
        instruction_count);

    for (uint32_t i = 0; i < switch_count; i++)
    {
      int32_t target = (int32_t) yr_le32toh(yr_unaligned_u32(
          operand_data + 4 + i * 4));

      yr_set_integer(
          (int64_t) il_offset + instruction_size + target,
          out_obj,
          "classes[%i].methods[%i].instructions[%i].switch_targets[%i]",
          class_idx,
          method_idx,
          instruction_count,
          i);
    }

    yr_set_integer(
        opcode_value,
        out_obj,
        "classes[%i].methods[%i].opcodes[%i]",
        class_idx,
        method_idx,
        instruction_count);

    il_offset += instruction_size;
    instruction_count++;
  }

  yr_set_integer(
      instruction_count,
      out_obj,
      "classes[%i].methods[%i].number_of_instructions",
      class_idx,
      method_idx);
  yr_set_integer(
      instruction_count,
      out_obj,
      "classes[%i].methods[%i].instruction_count",
      class_idx,
      method_idx);
  yr_set_integer(
      instruction_count,
      out_obj,
      "classes[%i].methods[%i].number_of_opcodes",
      class_idx,
      method_idx);

  uint32_t handler_count = dotnet_parse_exception_sections(
      pe,
      out_obj,
      class_idx,
      method_idx,
      body_offset,
      header_size,
      code_size,
      flags);

  yr_set_integer(
      handler_count,
      out_obj,
      "classes[%i].methods[%i].number_of_exception_handlers",
      class_idx,
      method_idx);
  yr_set_integer(
      handler_count,
      out_obj,
      "classes[%i].methods[%i].exception_handler_count",
      class_idx,
      method_idx);
  yr_set_integer(
      handler_count,
      out_obj,
      "classes[%i].methods[%i].number_of_exception_regions",
      class_idx,
      method_idx);
}

static void parse_methods(
    const CLASS_CONTEXT* ctx,
    uint32_t methodlist,
    uint32_t method_count,
    uint32_t class_idx,  // class index in the YARA output
    GENERIC_PARAMETERS* class_gen_params)
{
  if (!methodlist)
    return;

  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  uint32_t out_idx = 0;
  for (uint32_t idx = 0; idx < method_count; ++idx)
  {
    const uint8_t* data = get_table_offset(
        &ctx->tables->methoddef, methodlist + idx);

    if (!data)
      break;

    METHODDEF_ROW row = {0};
    bool result = read_methoddef(ctx, data, &row);
    if (!result)
      continue;

    if (row.Signature >= ctx->blob_size)
      continue;  

    const char* name = pe_get_dotnet_string(
        ctx->pe, str_heap, str_size, row.Name);

    // Ignore invalid/empty names
    if (!name || !*name)
      continue;

    // Try to find generic params for the method
    GENERIC_PARAMETERS method_gen_params = {0};
    parse_generic_params(ctx, true, methodlist + idx, &method_gen_params);

    // Read the blob entry with signature data
    const uint8_t* sig_data = ctx->blob_heap + row.Signature;

    BLOB_PARSE_RESULT blob_res = dotnet_parse_blob_entry(ctx->pe, sig_data);
    sig_data += blob_res.size;
    uint32_t sig_len = blob_res.length;
    uint32_t param_count = 0;

    char* return_type = NULL;
    // If there is valid blob and at least minimum to parse
    // (flags, paramCount, retType) parse these basic information
    if (blob_res.size && sig_len >= 3)
    {
      uint8_t flags = read_u8(&sig_data);
      sig_len -= 1;
      if (flags & SIG_FLAG_GENERIC)
        // Generic param count, ignored as we get the
        // information from generic param table
        (void) read_blob_unsigned(&sig_data, &sig_len);

      // Regular param count
      param_count = read_blob_unsigned(&sig_data, &sig_len);
      return_type = parse_signature_type(
          ctx, &sig_data, &sig_len, class_gen_params, &method_gen_params, 0);
    }
    else  // Error, skip
      goto clean_next;

    // Sanity check for corrupted files
    if (!return_type || param_count > MAX_PARAM_COUNT)
      goto clean_next;

    result = parse_method_params(
        ctx,
        row.ParamList,
        out_idx,
        class_idx,
        param_count,
        sig_data,
        sig_len,
        class_gen_params,
        &method_gen_params);

    if (!result)
      goto clean_next;

    dotnet_parse_method_body(ctx->pe, row.Rva, class_idx, out_idx);

    const char* visibility = get_method_visibility(row.Flags);
    uint32_t stat = (row.Flags & METHOD_ATTR_STATIC) != 0;
    uint32_t final = (row.Flags & METHOD_ATTR_FINAL) != 0;
    uint32_t virtual = (row.Flags & METHOD_ATTR_VIRTUAL) != 0;
    uint32_t abstract = (row.Flags & METHOD_ATTR_ABSTRACT) != 0;

    YR_OBJECT* out_obj = ctx->pe->object;
    yr_set_string(
        name, out_obj, "classes[%i].methods[%i].name", class_idx, out_idx);
    yr_set_string(
        visibility,
        out_obj,
        "classes[%i].methods[%i].visibility",
        class_idx,
        out_idx);
    yr_set_integer(
        stat, out_obj, "classes[%i].methods[%i].static", class_idx, out_idx);
    yr_set_integer(
        virtual,
        out_obj,
        "classes[%i].methods[%i].virtual",
        class_idx,
        out_idx);
    yr_set_integer(
        final, out_obj, "classes[%i].methods[%i].final", class_idx, out_idx);
    yr_set_integer(
        abstract,
        out_obj,
        "classes[%i].methods[%i].abstract",
        class_idx,
        out_idx);
    yr_set_integer(
        method_gen_params.len,
        out_obj,
        "classes[%i].methods[%i].number_of_generic_parameters",
        class_idx,
        out_idx);

    for (uint32_t i = 0; i < method_gen_params.len; ++i)
    {
      yr_set_string(
          method_gen_params.names[i],
          ctx->pe->object,
          "classes[%i].methods[%i].generic_parameters[%i]",
          class_idx,
          out_idx,
          i);
    }

    // Unset return type for constructors for FileInfo compatibility
    if (strcmp(name, ".ctor") != 0 && strcmp(name, ".cctor") != 0)
    {
      yr_set_string(
          return_type,
          out_obj,
          "classes[%i].methods[%i].return_type",
          class_idx,
          out_idx);
    }

    out_idx++;
  clean_next:
    yr_free(return_type);
    yr_free(method_gen_params.names);
  }

  yr_set_integer(
      out_idx, ctx->pe->object, "classes[%i].number_of_methods", class_idx);
}

// Walks NestedClass table, returns enclosing type fullname or NULL
static char* parse_enclosing_types(
    const CLASS_CONTEXT* ctx,
    uint32_t nested_idx,
    uint32_t depth)
{
  if (depth > MAX_NAMESPACE_DEPTH)
    return NULL;

  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  for (uint32_t idx = 0; idx < ctx->tables->nestedclass.RowCount; ++idx)
  {
    const uint8_t* nested_data = get_table_offset(
        &ctx->tables->nestedclass, idx + 1);

    NESTEDCLASS_ROW nested_row = {0};
    bool read_result = read_nestedclass(ctx, nested_data, &nested_row);
    if (!read_result)
      continue;

    // We found enclosing class, get the namespace
    if (nested_row.NestedClass == nested_idx)
    {
      const uint8_t* typedef_data = get_table_offset(
          &ctx->tables->typedef_, nested_row.EnclosingClass);

      TYPEDEF_ROW typedef_row = {0};
      bool result = read_typedef(ctx, typedef_data, &typedef_row);
      if (!result)
        break;

      const char* name = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, typedef_row.Name);

      // Skip the Module pseudo class
      if (name && strcmp(name, "<Module>") == 0)
        break;

      const char* namespace = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, typedef_row.Namespace);

      // Type might be further nested, try to find correct namespace,
      // check for self-reference
      if (is_nested(typedef_row.Flags) &&
          nested_row.EnclosingClass != nested_row.NestedClass)
      {
        char* nested_namespace = parse_enclosing_types(
            ctx, nested_row.EnclosingClass, depth + 1);

        char* tmp = create_full_name(namespace, nested_namespace);
        char* fullname = create_full_name(name, tmp);
        yr_free(nested_namespace);
        yr_free(tmp);
        return fullname;
      }

      return create_full_name(name, namespace);
    }
  }

  return NULL;
}

// Parses and reconstructs user defined types with their methods and base types
static void parse_user_types(const CLASS_CONTEXT* ctx)
{
  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  // Index for output tracking, we can't use
  // offset as some classes can get skipped
  uint32_t out_idx = 0;
  // skip first class as it's module pseudo class -> start at index 1
  for (uint32_t idx = 0; idx < ctx->tables->typedef_.RowCount; ++idx)
  {
    YR_OBJECT* out_obj = ctx->pe->object;
    // Tables indexing starts at 1
    const uint8_t* data = get_table_offset(&ctx->tables->typedef_, idx + 1);

    TYPEDEF_ROW row = {0};
    bool result = read_typedef(ctx, data, &row);
    if (!result)
      continue;

    const char* name = pe_get_dotnet_string(
        ctx->pe, str_heap, str_size, row.Name);
    const char* type = get_typedef_type(row.Flags);

    // Ignore invalid types and invalid (empty) names
    if (!name || !*name || !type)
      continue;

    // If the type is generic, it will include ` at the end of a name
    // with number of generic arguments, just use the part before that
    const char* end = strchr(name, '`');
    // If the name will turn out empty, skip it and skip Module pseudo class
    if (end == name || strcmp(name, "<Module>") == 0)
      continue;

    if (end)
      yr_set_sized_string(
          name, end - name, out_obj, "classes[%i].name", out_idx);
    else
      yr_set_string(name, out_obj, "classes[%i].name", out_idx);

    char* fullname = NULL;
    char* namespace = pe_get_dotnet_string(
        ctx->pe, str_heap, str_size, row.Namespace);

    // Type might be nested, if so -> find correct namespace
    if (is_nested(row.Flags))
    {
      char* nested_namespace = parse_enclosing_types(ctx, idx + 1, 1);
      namespace = create_full_name(namespace, nested_namespace);
      yr_set_string(namespace, out_obj, "classes[%i].namespace", out_idx);
      fullname = create_full_name(name, namespace);
      yr_free(nested_namespace);
      yr_free(namespace);
    }
    else
    {
      yr_set_string(namespace, out_obj, "classes[%i].namespace", out_idx);
      fullname = create_full_name(name, namespace);
    }

    const char* visibility = get_type_visibility(row.Flags);
    uint32_t abstract = (row.Flags & TYPE_ATTR_ABSTRACT) != 0;
    uint32_t sealed = (row.Flags & TYPE_ATTR_SEALED) != 0;

    yr_set_string(fullname, out_obj, "classes[%i].fullname", out_idx);
    yr_set_string(visibility, out_obj, "classes[%i].visibility", out_idx);
    yr_set_string(type, out_obj, "classes[%i].type", out_idx);
    yr_set_integer(abstract, out_obj, "classes[%i].abstract", out_idx);
    yr_set_integer(sealed, out_obj, "classes[%i].sealed", out_idx);

    yr_free(fullname);

    // Find if type has any Generic parameters
    GENERIC_PARAMETERS gen_params = {0};
    parse_generic_params(ctx, false, idx + 1, &gen_params);

    yr_set_integer(
        gen_params.len,
        out_obj,
        "classes[%i].number_of_generic_parameters",
        out_idx);

    for (uint32_t i = 0; i < gen_params.len; ++i)
    {
      yr_set_string(
          gen_params.names[i],
          out_obj,
          "classes[%i].generic_parameters[%i]",
          out_idx,
          i);
    }
    // Find type and interfaces the type inherits
    parse_type_parents(ctx, row.Extends, idx + 1, out_idx, &gen_params);

    // To get the number of methods, we must peek where the MethodList
    // of the next type is, then there is next.MethodList - this.MethodList
    // number of methods, or if there is no following type,
    // the rest of the MethodDef table is used
    uint32_t method_count = 0;
    // If there is next method
    if (idx + 1 < ctx->tables->typedef_.RowCount)
    {
      const uint8_t* data = get_table_offset(&ctx->tables->typedef_, idx + 2);

      TYPEDEF_ROW next_row = {0};
      result = read_typedef(ctx, data, &next_row);

      // overflow check
      if (result && next_row.Method >= row.Method)
        method_count = next_row.Method - row.Method;
    }
    // overflow check - use the rest of the methods in the table
    else if (ctx->tables->methoddef.RowCount >= row.Method)
    {
      method_count = ctx->tables->methoddef.RowCount + 1 - row.Method;
    }

    // Sanity check for corrupted files
    if (method_count <= MAX_METHOD_COUNT)
      parse_methods(ctx, row.Method, method_count, out_idx, &gen_params);

    yr_free(gen_params.names);
    out_idx++;
  }

  yr_set_integer(out_idx, ctx->pe->object, "number_of_classes");
}

void dotnet_parse_guid(
    PE* pe,
    int64_t metadata_root,
    PSTREAM_HEADER guid_header)
{
  // GUIDs are 16 bytes each, converted to hex format plus separators and NULL.
  char guid[37];
  int i = 0;

  const uint8_t* guid_offset = pe->data + metadata_root +
                               yr_le32toh(guid_header->Offset);

  DWORD guid_size = yr_le32toh(guid_header->Size);

  // Limit the number of GUIDs to 16.
  guid_size = yr_min(guid_size, 256);

  // Parse GUIDs if we have them. GUIDs are 16 bytes each.
  while (guid_size >= 16 && fits_in_pe(pe, guid_offset, 16))
  {
    sprintf(
        guid,
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        yr_le32toh(yr_unaligned_u32(guid_offset)),
        yr_le16toh(yr_unaligned_u16(guid_offset + 4)),
        yr_le16toh(yr_unaligned_u16(guid_offset + 6)),
        *(guid_offset + 8),
        *(guid_offset + 9),
        *(guid_offset + 10),
        *(guid_offset + 11),
        *(guid_offset + 12),
        *(guid_offset + 13),
        *(guid_offset + 14),
        *(guid_offset + 15));

    guid[(16 * 2) + 4] = '\0';

    yr_set_string(guid, pe->object, "guids[%i]", i);

    i++;
    guid_size -= 16;
    guid_offset += 16;
  }

  yr_set_integer(i, pe->object, "number_of_guids");
}

void dotnet_parse_us(PE* pe, int64_t metadata_root, PSTREAM_HEADER us_header)
{
  BLOB_PARSE_RESULT blob_result;
  int i = 0;

  const uint32_t ush_sz = yr_le32toh(us_header->Size);

  const uint8_t* offset = pe->data + metadata_root +
                          yr_le32toh(us_header->Offset);
  const uint8_t* end_of_header = offset + ush_sz;

  // Make sure the header size is larger than 0 and its end is not past the
  // end of PE.
  if (ush_sz == 0 || !fits_in_pe(pe, offset, ush_sz))
    return;

  // The first entry MUST be single NULL byte.
  if (*offset != 0x00)
    return;

  offset++;

  while (offset < end_of_header)
  {
    blob_result = dotnet_parse_blob_entry(pe, offset);

    if (blob_result.size == 0)
      break;

    offset += blob_result.size;
    // There is an additional terminal byte which is 0x01 under certain
    // conditions - when any top bit in utf16 top byte is set.
    // The exact conditions are not relevant to our parsing but are
    // documented in ECMA-335 II.24.2.4.
    if (blob_result.length > 0)
      blob_result.length--;

    // Avoid empty strings, which usually happen as padding at the end of the
    // stream.
    if (blob_result.length > 0 && fits_in_pe(pe, offset, blob_result.length))
    {
      yr_set_sized_string(
          (char*) offset,
          blob_result.length,
          pe->object,
          "user_strings[%i]",
          i);

      offset += blob_result.length;
      i++;
    }
  }

  yr_set_integer(i, pe->object, "number_of_user_strings");
}

STREAMS dotnet_parse_stream_headers(
    PE* pe,
    int64_t offset,
    int64_t metadata_root,
    DWORD num_streams)
{
  PSTREAM_HEADER stream_header;
  STREAMS headers;

  char* start;
  char* eos;
  char stream_name[DOTNET_STREAM_NAME_SIZE + 1];
  unsigned int i;

  memset(&headers, '\0', sizeof(STREAMS));
  headers.metadata_root = metadata_root;

  stream_header = (PSTREAM_HEADER) (pe->data + offset);

  for (i = 0; i < num_streams; i++)
  {
    if (!struct_fits_in_pe(pe, stream_header, STREAM_HEADER))
      break;

    start = (char*) stream_header->Name;

    if (!fits_in_pe(pe, start, DOTNET_STREAM_NAME_SIZE))
      break;

    eos = (char*) memmem((void*) start, DOTNET_STREAM_NAME_SIZE, "\0", 1);

    if (eos == NULL)
      break;

    strncpy(stream_name, stream_header->Name, DOTNET_STREAM_NAME_SIZE);
    stream_name[DOTNET_STREAM_NAME_SIZE] = '\0';

    yr_set_string(stream_name, pe->object, "streams[%i].name", i);

    // Offset is relative to metadata_root.
    yr_set_integer(
        metadata_root + yr_le32toh(stream_header->Offset),
        pe->object,
        "streams[%i].offset",
        i);

    yr_set_integer(
        yr_le32toh(stream_header->Size), pe->object, "streams[%i].size", i);

    // Store necessary bits to parse these later. Not all tables will be
    // parsed, but are referenced from others. For example, the #Strings
    // stream is referenced from various tables in the #~ heap.
    //
    // #- is not documented but it represents unoptimized metadata stream. It
    // may contain additional tables such as FieldPtr, ParamPtr, MethodPtr or
    // PropertyPtr for indirect referencing. We already take into account these
    // tables and they do not interfere with anything we parse in this module.

    if ((strncmp(stream_name, "#~", 2) == 0 ||
         strncmp(stream_name, "#-", 2) == 0) &&
        headers.tilde == NULL)
      headers.tilde = stream_header;
    else if (strncmp(stream_name, "#GUID", 5) == 0)
      headers.guid = stream_header;
    else if (strncmp(stream_name, "#Strings", 8) == 0 && headers.string == NULL)
      headers.string = stream_header;
    else if (strncmp(stream_name, "#Blob", 5) == 0 && headers.blob == NULL)
      headers.blob = stream_header;
    else if (strncmp(stream_name, "#US", 3) == 0 && headers.us == NULL)
      headers.us = stream_header;

    // Stream name is padded to a multiple of 4.
    stream_header = (PSTREAM_HEADER) ((uint8_t*) stream_header +
                                      sizeof(STREAM_HEADER) +
                                      strlen(stream_name) + 4 -
                                      (strlen(stream_name) % 4));
  }

  yr_set_integer(i, pe->object, "number_of_streams");

  return headers;
}

// This is the second pass through the data for #~. The first pass collects
// information on the number of rows for tables which have coded indexes.
// This pass uses that information and the index_sizes to parse the tables
// of interest.
//
// Because the indexes can vary in size depending upon the number of rows in
// other tables it is impossible to use static sized structures. To deal with
// this hardcode the sizes of each table based upon the documentation (for the
// static sized portions) and use the variable sizes accordingly.

void dotnet_parse_tilde_2(
    PE* pe,
    PTILDE_HEADER tilde_header,
    int64_t resource_base,
    ROWS rows,
    INDEX_SIZES index_sizes,
    PSTREAMS streams)
{
  PMODULE_TABLE module_table;
  PASSEMBLY_TABLE assembly_table;
  PASSEMBLYREF_TABLE assemblyref_table;
  PFIELDRVA_TABLE fieldrva_table;
  PMANIFESTRESOURCE_TABLE manifestresource_table;
  PMODULEREF_TABLE moduleref_table;
  PCUSTOMATTRIBUTE_TABLE customattribute_table;
  PCONSTANT_TABLE constant_table;
  DWORD resource_size, implementation;

  // To save important data for future processing, initialize everything to 0
  TABLES tables = {0};

  char* name;
  char typelib[MAX_TYPELIB_SIZE + 1];
  unsigned int i;
  int bit_check;
  int matched_bits = 0;

  int64_t metadata_root = streams->metadata_root;
  int64_t resource_offset, field_offset;
  uint32_t row_size, row_count, counter, str_heap_size;

  const uint8_t* string_offset;
  const uint8_t* blob_offset;

  const uint8_t* tilde_stream_end = pe->data + metadata_root +
                                    yr_le32toh(streams->tilde->Offset) +
                                    yr_le32toh(streams->tilde->Size);

  uint32_t num_rows = 0;
  uint32_t valid_rows = 0;
  uint32_t* row_offset = NULL;
  uint8_t* table_offset = NULL;
  uint8_t* row_ptr = NULL;

  // These are pointers and row sizes for tables of interest to us for special
  // parsing. For example, we are interested in pulling out any CustomAttributes
  // that are GUIDs so we need to be able to walk these tables. To find GUID
  // CustomAttributes you need to walk the CustomAttribute table and look for
  // any row with a Parent that indexes into the Assembly table and Type indexes
  // into the MemberRef table. Then you follow the index into the MemberRef
  // table and check the Class to make sure it indexes into TypeRef table. If it
  // does you follow that index and make sure the Name is "GuidAttribute". If
  // all that is valid then you can take the Value from the CustomAttribute
  // table to find out the index into the Blob stream and parse that.
  //
  // Luckily we can abuse the fact that the order of the tables is guaranteed
  // consistent (though some may not exist, but if they do exist they must exist
  // in a certain order). The order is defined by their position in the Valid
  // member of the tilde_header structure. By the time we are parsing the
  // CustomAttribute table we have already recorded the location of the TypeRef
  // and MemberRef tables, so we can follow the chain back up from
  // CustomAttribute through MemberRef to TypeRef.

  uint8_t* typeref_ptr = NULL;
  uint8_t* memberref_ptr = NULL;
  uint32_t typeref_row_size = 0;
  uint32_t memberref_row_size = 0;
  uint8_t* typeref_row = NULL;
  uint8_t* memberref_row = NULL;

  DWORD type_index;
  DWORD class_index;
  BLOB_PARSE_RESULT blob_result;
  DWORD blob_index;
  DWORD blob_length;

  // These are used to determine the size of coded indexes, which are the
  // dynamically sized columns for some tables. The coded indexes are
  // documented in ECMA-335 Section II.24.2.6.
  uint8_t index_size, index_size2;

  // Number of rows is the number of bits set to 1 in Valid.
  // Count number of Rows size entries in header to skip over them
  valid_rows = yr_popcount64(yr_le64toh(tilde_header->Valid));

  row_offset = (uint32_t*) (tilde_header + 1);
  table_offset = (uint8_t*) row_offset;
  table_offset += sizeof(uint32_t) * valid_rows;

  // Sometimes files have some sort of padding after, from DnSpy source
  // it's denoted by EXTRA_DATA 0x40 flag in heapflags
  // We then need to offset by 4 bytes, otherwise the analysis is wrong
  // https://github.com/dnSpy/dnSpy/blob/2b6dcfaf602fb8ca6462b8b6237fdfc0c74ad994/dnSpy/dnSpy/Hex/Files/DotNet/TablesHeaderDataImpl.cs
  // example: 1c2246af11000c3ce6b05ed6ba25060cbb00273c599428b98cf4013bdd82892f
  if (tilde_header->HeapSizes & HEAP_EXTRA_DATA)
    table_offset += 4;

#define DOTNET_STRING_INDEX(Name)                       \
  index_sizes.string == 2 ? yr_le16toh(Name.Name_Short) \
                          : yr_le32toh(Name.Name_Long)

  string_offset = pe->data + metadata_root +
                  yr_le32toh(streams->string->Offset);

  str_heap_size = yr_le32toh(streams->string->Size);

  // Now walk again this time parsing out what we care about.
  for (bit_check = 0; bit_check < 64; bit_check++)
  {
    // If the Valid bit is not set for this table, skip it...
    if (!((yr_le64toh(tilde_header->Valid) >> bit_check) & 0x01))
      continue;

    if (!fits_in_pe(pe, row_offset + matched_bits, sizeof(uint32_t)) ||
        (uint8_t*) (row_offset + matched_bits + 1) > tilde_stream_end)
      return;

    num_rows = yr_le32toh(*(row_offset + matched_bits));

    // Make sure that num_rows has a reasonable value. For example
    // edc05e49dd3810be67942b983455fd43 sets a large value for number of
    // rows for the BIT_MODULE section.
    if (num_rows > 15000)
      return;

    // Those tables which exist, but that we don't care about must be
    // skipped.
    //
    // Sadly, given the dynamic sizes of some columns we can not have well
    // defined structures for all tables and use them accordingly. To deal
    // with this manually move the table_offset pointer by the appropriate
    // number of bytes as described in the documentation for each table.
    //
    // The table structures are documented in ECMA-335 Section II.22.

    switch (bit_check)
    {
    case BIT_MODULE:
      module_table = (PMODULE_TABLE) table_offset;

      if (!struct_fits_in_pe(pe, module_table, MODULE_TABLE))
        break;

      name = pe_get_dotnet_string(
          pe,
          string_offset,
          str_heap_size,
          DOTNET_STRING_INDEX(module_table->Name));

      if (name != NULL)
        yr_set_string(name, pe->object, "module_name");

      row_size = 2 + index_sizes.string + (index_sizes.guid * 3);

      tables.module.Offset = table_offset;
      tables.module.RowCount = num_rows;
      tables.module.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_TYPEREF:
      row_count = max_rows(
          4,
          yr_le32toh(rows.module),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.typeref));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = (index_size + (index_sizes.string * 2));
      typeref_row_size = row_size;
      typeref_ptr = table_offset;

      tables.typeref.Offset = table_offset;
      tables.typeref.RowCount = num_rows;
      tables.typeref.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_TYPEDEF:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = 4 + (index_sizes.string * 2) + index_size + index_sizes.field +
                 index_sizes.methoddef;

      tables.typedef_.Offset = table_offset;
      tables.typedef_.RowCount = num_rows;
      tables.typedef_.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_FIELDPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.field) * num_rows;
      break;

    case BIT_FIELD:
      table_offset += (2 + (index_sizes.string) + index_sizes.blob) * num_rows;
      break;

    case BIT_METHODDEFPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.methoddef) * num_rows;
      break;

    case BIT_METHODDEF:
      row_size = 4 + 2 + 2 + index_sizes.string + index_sizes.blob +
                 index_sizes.param;

      tables.methoddef.Offset = table_offset;
      tables.methoddef.RowCount = num_rows;
      tables.methoddef.RowSize = row_size;
      table_offset += row_size * num_rows;
      break;

    case BIT_PARAM:
      row_size = 2 + 2 + index_sizes.string;

      tables.param.Offset = table_offset;
      tables.param.RowCount = num_rows;
      tables.param.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_INTERFACEIMPL:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = index_sizes.typedef_ + index_size;

      tables.intefaceimpl.Offset = table_offset;
      tables.intefaceimpl.RowCount = num_rows;
      tables.intefaceimpl.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_MEMBERREF:
      row_count = max_rows(
          4,
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x03))
        index_size = 4;
      else
        index_size = 2;

      row_size = (index_size + index_sizes.string + index_sizes.blob);
      memberref_row_size = row_size;
      memberref_ptr = table_offset;
      table_offset += row_size * num_rows;
      break;

    case BIT_CONSTANT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.param),
          yr_le32toh(rows.field),
          yr_le32toh(rows.property));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      // Using 'i' is insufficent since we may skip certain constants and
      // it would give an inaccurate count in that case.
      counter = 0;
      row_size = (1 + 1 + index_size + index_sizes.blob);
      row_ptr = table_offset;

      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        constant_table = (PCONSTANT_TABLE) row_ptr;

        // Only look for constants of type string.
        if (yr_le32toh(constant_table->Type) != TYPE_STRING)
        {
          row_ptr += row_size;
          continue;
        }

        // Get the blob offset and pull it out of the blob table.
        blob_offset = ((uint8_t*) constant_table) + 2 + index_size;

        if (index_sizes.blob == 4)
          blob_index = yr_unaligned_u32(blob_offset);
        else
          // Cast the value (index into blob table) to a 32bit value.
          blob_index = (DWORD) (yr_unaligned_u16(blob_offset));

        // Everything checks out. Make sure the index into the blob field
        // is valid (non-null and within range).
        blob_offset = pe->data + metadata_root +
                      yr_le32toh(streams->blob->Offset) + blob_index;

        blob_result = dotnet_parse_blob_entry(pe, blob_offset);

        if (blob_result.size == 0)
        {
          row_ptr += row_size;
          continue;
        }

        blob_length = blob_result.length;
        blob_offset += blob_result.size;

        // Quick sanity check to make sure the blob entry is within bounds.
        if (blob_offset + blob_length >= pe->data + pe->data_size)
        {
          row_ptr += row_size;
          continue;
        }

        yr_set_sized_string(
            (char*) blob_offset,
            blob_result.length,
            pe->object,
            "constants[%i]",
            counter);

        counter++;
        row_ptr += row_size;
      }

      yr_set_integer(counter, pe->object, "number_of_constants");
      table_offset += row_size * num_rows;
      break;

    case BIT_CUSTOMATTRIBUTE:
      // index_size is size of the parent column.
      row_count = max_rows(
          21,
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.field),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.param),
          yr_le32toh(rows.interfaceimpl),
          yr_le32toh(rows.memberref),
          yr_le32toh(rows.module),
          yr_le32toh(rows.property),
          yr_le32toh(rows.event),
          yr_le32toh(rows.standalonesig),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.typespec),
          yr_le32toh(rows.assembly),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.file),
          yr_le32toh(rows.exportedtype),
          yr_le32toh(rows.manifestresource),
          yr_le32toh(rows.genericparam),
          yr_le32toh(rows.genericparamconstraint),
          yr_le32toh(rows.methodspec));

      if (row_count > (0xFFFF >> 0x05))
        index_size = 4;
      else
        index_size = 2;

      // index_size2 is size of the type column.
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x03))
        index_size2 = 4;
      else
        index_size2 = 2;

      row_size = (index_size + index_size2 + index_sizes.blob);

      if (typeref_ptr != NULL && memberref_ptr != NULL)
      {
        row_ptr = table_offset;

        for (i = 0; i < num_rows; i++)
        {
          if (!fits_in_pe(pe, row_ptr, row_size))
            break;

          // Check the Parent field.
          customattribute_table = (PCUSTOMATTRIBUTE_TABLE) row_ptr;

          if (index_size == 4)
          {
            // Low 5 bits tell us what this is an index into. Remaining bits
            // tell us the index value.
            // Parent must be an index into the Assembly (0x0E) table.
            if ((yr_unaligned_u32(customattribute_table) & 0x1F) != 0x0E)
            {
              row_ptr += row_size;
              continue;
            }
          }
          else
          {
            // Low 5 bits tell us what this is an index into. Remaining bits
            // tell us the index value.
            // Parent must be an index into the Assembly (0x0E) table.
            if ((yr_unaligned_u16(customattribute_table) & 0x1F) != 0x0E)
            {
              row_ptr += row_size;
              continue;
            }
          }

          // Check the Type field.
          customattribute_table = (PCUSTOMATTRIBUTE_TABLE) (row_ptr +
                                                            index_size);

          if (index_size2 == 4)
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Only values 2 and 3 are defined.
            // Type must be an index into the MemberRef table.
            if ((yr_unaligned_u32(customattribute_table) & 0x07) != 0x03)
            {
              row_ptr += row_size;
              continue;
            }

            type_index = yr_unaligned_u32(customattribute_table) >> 3;
          }
          else
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Only values 2 and 3 are defined.
            // Type must be an index into the MemberRef table.
            if ((yr_unaligned_u16(customattribute_table) & 0x07) != 0x03)
            {
              row_ptr += row_size;
              continue;
            }

            // Cast the index to a 32bit value.
            type_index = (DWORD) (yr_unaligned_u16(customattribute_table) >> 3);
          }

          if (type_index > 0)
            type_index--;

          // Now follow the Type index into the MemberRef table.
          memberref_row = memberref_ptr + (memberref_row_size * type_index);

          if (!fits_in_pe(pe, memberref_row, memberref_row_size))
            break;

          if (index_sizes.memberref == 4)
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Class must be an index into the
            // TypeRef table.
            if ((yr_unaligned_u32(memberref_row) & 0x07) != 0x01)
            {
              row_ptr += row_size;
              continue;
            }

            class_index = yr_unaligned_u32(memberref_row) >> 3;
          }
          else
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Class must be an index into the
            // TypeRef table.
            if ((yr_unaligned_u16(memberref_row) & 0x07) != 0x01)
            {
              row_ptr += row_size;
              continue;
            }

            // Cast the index to a 32bit value.
            class_index = (DWORD) (yr_unaligned_u16(memberref_row) >> 3);
          }

          if (class_index > 0)
            class_index--;

          // Now follow the Class index into the TypeRef table.
          typeref_row = typeref_ptr + (typeref_row_size * class_index);

          if (!fits_in_pe(pe, typeref_row, typeref_row_size))
            break;

          // Skip over the ResolutionScope and check the Name field,
          // which is an index into the Strings heap.
          row_count = max_rows(
              4,
              yr_le32toh(rows.module),
              yr_le32toh(rows.moduleref),
              yr_le32toh(rows.assemblyref),
              yr_le32toh(rows.typeref));

          if (row_count > (0xFFFF >> 0x02))
            typeref_row += 4;
          else
            typeref_row += 2;

          if (index_sizes.string == 4)
          {
            name = pe_get_dotnet_string(
                pe,
                string_offset,
                str_heap_size,
                yr_unaligned_u32(typeref_row));
          }
          else
          {
            name = pe_get_dotnet_string(
                pe,
                string_offset,
                str_heap_size,
                yr_unaligned_u16(typeref_row));
          }

          if (name != NULL && strncmp(name, "GuidAttribute", 13) != 0)
          {
            row_ptr += row_size;
            continue;
          }

          // Get the Value field.
          customattribute_table = (PCUSTOMATTRIBUTE_TABLE) (row_ptr +
                                                            index_size +
                                                            index_size2);

          if (index_sizes.blob == 4)
            blob_index = yr_unaligned_u32(customattribute_table);
          else
            // Cast the value (index into blob table) to a 32bit value.
            blob_index = (DWORD) (yr_unaligned_u16(customattribute_table));

          // Everything checks out. Make sure the index into the blob field
          // is valid (non-null and within range).
          blob_offset = pe->data + metadata_root +
                        yr_le32toh(streams->blob->Offset) + blob_index;

          // If index into blob is 0 or past the end of the blob stream, skip
          // it. We don't know the size of the blob entry yet because that is
          // encoded in the start.
          if (blob_index == 0x00 || blob_offset >= pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          blob_result = dotnet_parse_blob_entry(pe, blob_offset);

          if (blob_result.size == 0)
          {
            row_ptr += row_size;
            continue;
          }

          blob_length = blob_result.length;
          blob_offset += blob_result.size;

          // Quick sanity check to make sure the blob entry is within bounds
          // and its length is at least 3 (2 bytes for the 16 bits prolog and
          // 1 byte for the string length)
          if (blob_length < 3 ||
              blob_offset + blob_length >= pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          // Custom attributes MUST have a 16 bit prolog of 0x0001
          if (yr_unaligned_u16(blob_offset) != 0x0001)
          {
            row_ptr += row_size;
            continue;
          }

          // The next byte after the 16 bit prolog is the length of the string.
          blob_offset += 2;
          uint8_t str_len = *blob_offset;

          // Increment blob_offset so that it points to the first byte of the
          // string.
          blob_offset += 1;

          if (blob_offset + str_len > pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          if (*blob_offset == 0xFF || *blob_offset == 0x00)
          {
            typelib[0] = '\0';
          }
          else
          {
            strncpy(typelib, (char*) blob_offset, str_len);
            typelib[str_len] = '\0';
          }

          yr_set_string(typelib, pe->object, "typelib");

          row_ptr += row_size;
        }
      }

      table_offset += row_size * num_rows;
      break;

    case BIT_FIELDMARSHAL:
      row_count = max_rows(2, yr_le32toh(rows.field), yr_le32toh(rows.param));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_DECLSECURITY:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.assembly));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_CLASSLAYOUT:
      table_offset += (2 + 4 + index_sizes.typedef_) * num_rows;
      break;

    case BIT_FIELDLAYOUT:
      table_offset += (4 + index_sizes.field) * num_rows;
      break;

    case BIT_STANDALONESIG:
      table_offset += (index_sizes.blob) * num_rows;
      break;

    case BIT_EVENTMAP:
      table_offset += (index_sizes.typedef_ + index_sizes.event) * num_rows;
      break;

    case BIT_EVENTPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.event) * num_rows;
      break;

    case BIT_EVENT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_sizes.string + index_size) * num_rows;
      break;

    case BIT_PROPERTYMAP:
      table_offset += (index_sizes.typedef_ + index_sizes.property) * num_rows;
      break;

    case BIT_PROPERTYPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.property) * num_rows;
      break;

    case BIT_PROPERTY:
      table_offset += (2 + index_sizes.string + index_sizes.blob) * num_rows;
      break;

    case BIT_METHODSEMANTICS:
      row_count = max_rows(
          2, yr_le32toh(rows.event), yr_le32toh(rows.property));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_sizes.methoddef + index_size) * num_rows;
      break;

    case BIT_METHODIMPL:
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_sizes.typedef_ + (index_size * 2)) * num_rows;
      break;

    case BIT_MODULEREF:
      row_ptr = table_offset;

      // Can't use 'i' here because we only set the string if it is not
      // NULL. Instead use 'counter'.
      counter = 0;

      for (i = 0; i < num_rows; i++)
      {
        moduleref_table = (PMODULEREF_TABLE) row_ptr;

        if (!struct_fits_in_pe(pe, moduleref_table, MODULEREF_TABLE))
          break;

        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            DOTNET_STRING_INDEX(moduleref_table->Name));

        if (name != NULL)
        {
          yr_set_string(name, pe->object, "modulerefs[%i]", counter);
          counter++;
        }

        row_ptr += index_sizes.string;
      }

      yr_set_integer(counter, pe->object, "number_of_modulerefs");

      row_size = index_sizes.string;

      tables.moduleref.Offset = table_offset;
      tables.moduleref.RowCount = num_rows;
      tables.moduleref.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_TYPESPEC:
      row_size = index_sizes.blob;

      tables.typespec.Offset = table_offset;
      tables.typespec.RowCount = num_rows;
      tables.typespec.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_IMPLMAP:
      row_count = max_rows(
          2, yr_le32toh(rows.field), yr_le32toh(rows.methoddef));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_size + index_sizes.string +
                       index_sizes.moduleref) *
                      num_rows;
      break;

    case BIT_FIELDRVA:
      row_size = 4 + index_sizes.field;
      row_ptr = table_offset;

      // Can't use 'i' here because we only set the field offset if it is
      // valid. Instead use 'counter'.
      counter = 0;

      for (i = 0; i < num_rows; i++)
      {
        fieldrva_table = (PFIELDRVA_TABLE) row_ptr;

        if (!struct_fits_in_pe(pe, fieldrva_table, FIELDRVA_TABLE))
          break;

        field_offset = pe_rva_to_offset(pe, fieldrva_table->RVA);

        if (field_offset >= 0)
        {
          yr_set_integer(
              field_offset, pe->object, "field_offsets[%i]", counter);
          counter++;
        }

        row_ptr += row_size;
      }

      yr_set_integer(counter, pe->object, "number_of_field_offsets");

      table_offset += row_size * num_rows;
      break;

    case BIT_ENCLOG:
      table_offset += (4 + 4) * num_rows;
      break;

    case BIT_ENCMAP:
      table_offset += (4) * num_rows;
      break;

    case BIT_ASSEMBLY:
      row_size =
          (4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob + (index_sizes.string * 2));

      if (!fits_in_pe(pe, table_offset, row_size))
        break;

      row_ptr = table_offset;
      assembly_table = (PASSEMBLY_TABLE) table_offset;

      yr_set_integer(
          yr_le16toh(assembly_table->MajorVersion),
          pe->object,
          "assembly.version.major");
      yr_set_integer(
          yr_le16toh(assembly_table->MinorVersion),
          pe->object,
          "assembly.version.minor");
      yr_set_integer(
          yr_le16toh(assembly_table->BuildNumber),
          pe->object,
          "assembly.version.build_number");
      yr_set_integer(
          yr_le16toh(assembly_table->RevisionNumber),
          pe->object,
          "assembly.version.revision_number");

      // Can't use assembly_table here because the PublicKey comes before
      // Name and is a variable length field.

      if (index_sizes.string == 4)
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            yr_le32toh(yr_unaligned_u32(
                row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));
      else
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            yr_le16toh(
                yr_unaligned_u16(
                    row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));

      if (name != NULL)
        yr_set_string(name, pe->object, "assembly.name");

      // Culture comes after Name.
      if (index_sizes.string == 4)
      {
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            yr_le32toh(yr_unaligned_u32(
                row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob +
                index_sizes.string)));
      }
      else
      {
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            yr_le16toh(yr_unaligned_u16(
                row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob +
                index_sizes.string)));
      }

      // Sometimes it will be a zero length string. This is technically
      // against the specification but happens from time to time.
      if (name != NULL && strlen(name) > 0)
        yr_set_string(name, pe->object, "assembly.culture");

      table_offset += row_size * num_rows;
      break;

    case BIT_ASSEMBLYPROCESSOR:
      table_offset += (4) * num_rows;
      break;

    case BIT_ASSEMBLYOS:
      table_offset += (4 + 4 + 4) * num_rows;
      break;

    case BIT_ASSEMBLYREF:
      row_size =
          (2 + 2 + 2 + 2 + 4 + (index_sizes.blob * 2) +
           (index_sizes.string * 2));

      row_ptr = table_offset;

      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        assemblyref_table = (PASSEMBLYREF_TABLE) row_ptr;

        yr_set_integer(
            yr_le16toh(assemblyref_table->MajorVersion),
            pe->object,
            "assembly_refs[%i].version.major",
            (int) i);
        yr_set_integer(
            yr_le16toh(assemblyref_table->MinorVersion),
            pe->object,
            "assembly_refs[%i].version.minor",
            i);
        yr_set_integer(
            yr_le16toh(assemblyref_table->BuildNumber),
            pe->object,
            "assembly_refs[%i].version.build_number",
            i);
        yr_set_integer(
            yr_le16toh(assemblyref_table->RevisionNumber),
            pe->object,
            "assembly_refs[%i].version.revision_number",
            i);

        blob_offset = pe->data + metadata_root +
                      yr_le32toh(streams->blob->Offset);

        if (index_sizes.blob == 4)
          blob_offset += yr_le32toh(
              assemblyref_table->PublicKeyOrToken.PublicKeyOrToken_Long);
        else
          blob_offset += yr_le16toh(
              assemblyref_table->PublicKeyOrToken.PublicKeyOrToken_Short);

        blob_result = dotnet_parse_blob_entry(pe, blob_offset);
        blob_offset += blob_result.size;

        if (blob_result.size == 0 ||
            !fits_in_pe(pe, blob_offset, blob_result.length))
        {
          row_ptr += row_size;
          continue;
        }

        // Avoid empty strings.
        if (blob_result.length > 0)
        {
          yr_set_sized_string(
              (char*) blob_offset,
              blob_result.length,
              pe->object,
              "assembly_refs[%i].public_key_or_token",
              i);
        }

        // Can't use assemblyref_table here because the PublicKey comes before
        // Name and is a variable length field.

        if (index_sizes.string == 4)
          name = pe_get_dotnet_string(
              pe,
              string_offset,
              str_heap_size,
              yr_le32toh(yr_unaligned_u32(
                  row_ptr + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));
        else
          name = pe_get_dotnet_string(
              pe,
              string_offset,
              str_heap_size,
              yr_le16toh(yr_unaligned_u16(
                  row_ptr + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));

        if (name != NULL)
          yr_set_string(name, pe->object, "assembly_refs[%i].name", i);

        row_ptr += row_size;
      }

      tables.assemblyref.Offset = table_offset;
      tables.assemblyref.RowCount = num_rows;
      tables.assemblyref.RowSize = row_size;

      yr_set_integer(i, pe->object, "number_of_assembly_refs");
      table_offset += row_size * num_rows;
      break;

    case BIT_ASSEMBLYREFPROCESSOR:
      table_offset += (4 + index_sizes.assemblyrefprocessor) * num_rows;
      break;

    case BIT_ASSEMBLYREFOS:
      table_offset += (4 + 4 + 4 + index_sizes.assemblyref) * num_rows;
      break;

    case BIT_FILE:
      table_offset += (4 + index_sizes.string + index_sizes.blob) * num_rows;
      break;

    case BIT_EXPORTEDTYPE:
      row_count = max_rows(
          3,
          yr_le32toh(rows.file),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.exportedtype));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (4 + 4 + (index_sizes.string * 2) + index_size) *
                      num_rows;
      break;

    case BIT_MANIFESTRESOURCE:
      // This is an Implementation coded index with no 3rd bit specified.
      row_count = max_rows(
          2, yr_le32toh(rows.file), yr_le32toh(rows.assemblyref));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = (4 + 4 + index_sizes.string + index_size);
      row_ptr = table_offset;

      // First DWORD is the offset.
      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        manifestresource_table = (PMANIFESTRESOURCE_TABLE) row_ptr;

        if (index_size == 4)
          implementation = yr_le32toh(
              yr_unaligned_u32(row_ptr + 4 + 4 + index_sizes.string));
        else
          implementation = yr_le16toh(
              yr_unaligned_u16(row_ptr + 4 + 4 + index_sizes.string));

        row_ptr += row_size;

        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            DOTNET_STRING_INDEX(manifestresource_table->Name));

        if (name != NULL)
          yr_set_string(name, pe->object, "resources[%i].name", i);

        // Only set offset and length if it is in this file, otherwise continue
        // with the next resource.
        if (implementation != 0)
          continue;

        resource_offset = yr_le32toh(manifestresource_table->Offset);

        if (!fits_in_pe(
                pe, pe->data + resource_base + resource_offset, sizeof(DWORD)))
          continue;

        resource_size = yr_le32toh(
            yr_unaligned_u32(pe->data + resource_base + resource_offset));

        // Add 4 to skip the size.
        yr_set_integer(
            resource_base + resource_offset + 4,
            pe->object,
            "resources[%i].offset",
            i);

        yr_set_integer(resource_size, pe->object, "resources[%i].length", i);
      }

      yr_set_integer(i, pe->object, "number_of_resources");

      table_offset += row_size * num_rows;
      break;

    case BIT_NESTEDCLASS:
      row_size = index_sizes.typedef_ * 2;

      tables.nestedclass.Offset = table_offset;
      tables.nestedclass.RowCount = num_rows;
      tables.nestedclass.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_GENERICPARAM:
      row_count = max_rows(
          2, yr_le32toh(rows.typedef_), yr_le32toh(rows.methoddef));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      row_size = (2 + 2 + index_size + index_sizes.string);

      tables.genericparam.Offset = table_offset;
      tables.genericparam.RowCount = num_rows;
      tables.genericparam.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_METHODSPEC:
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_GENERICPARAMCONSTRAINT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_sizes.genericparam + index_size) * num_rows;
      break;

    default:
      // printf("Unknown bit: %i\n", bit_check);
      return;
    }

    matched_bits++;
  }

  CLASS_CONTEXT class_context = {
      .pe = pe,
      .tables = &tables,
      .index_sizes = &index_sizes,
      .str_heap = string_offset,
      .str_size = str_heap_size,
      .blob_heap = pe->data + streams->metadata_root +
                   yr_le32toh(streams->blob->Offset),
      .blob_size = yr_le32toh(streams->blob->Size)};

  parse_user_types(&class_context);
}

// Parsing the #~ stream is done in two parts. The first part (this function)
// parses enough of the Stream to provide context for the second pass. In
// particular it is collecting the number of rows for each of the tables. The
// second part parses the actual tables of interest.

void dotnet_parse_tilde(PE* pe, PCLI_HEADER cli_header, PSTREAMS streams)
{
  int64_t resource_base;
  int64_t metadata_root = streams->metadata_root;
  uint32_t* row_offset = NULL;

  int bit_check;

  // This is used as an offset into the rows and tables. For every bit set in
  // Valid this will be incremented. This is because the bit position doesn't
  // matter, just the number of bits that are set, when determining how many
  // rows and what the table structure is.
  int matched_bits = 0;

  // We need to know the number of rows for some tables, because they are
  // indexed into. The index will be either 2 or 4 bytes, depending upon the
  // number of rows being indexed into.
  ROWS rows;
  INDEX_SIZES index_sizes;
  uint32_t heap_sizes;

  // Default all rows to 0. They will be set to actual values later on, if
  // they exist in the file.
  memset(&rows, '\0', sizeof(ROWS));

  // Default index sizes are 2. Will be bumped to 4 if necessary.
  memset(&index_sizes, 2, sizeof(index_sizes));

  const PTILDE_HEADER tilde_header = (PTILDE_HEADER) (pe->data + metadata_root +
                                  yr_le32toh(streams->tilde->Offset));

  const uint8_t* tilde_stream_end = pe->data + metadata_root +
                                    yr_le32toh(streams->tilde->Offset) +
                                    yr_le32toh(streams->tilde->Size);

  if (!struct_fits_in_pe(pe, tilde_header, TILDE_HEADER))
    return;

  heap_sizes = yr_le32toh(tilde_header->HeapSizes);

  // Set index sizes for various heaps.
  if (heap_sizes & 0x01)
    index_sizes.string = 4;

  if (heap_sizes & 0x02)
    index_sizes.guid = 4;

  if (heap_sizes & 0x04)
    index_sizes.blob = 4;

  // Immediately after the tilde header is an array of 32bit values which
  // indicate how many rows are in each table. The tables are immediately
  // after the rows array.
  //
  // Save the row offset.
  row_offset = (uint32_t*) (tilde_header + 1);

  uint32_t valid_count = yr_popcount64(yr_le64toh(tilde_header->Valid));
  
  if (!fits_in_pe(pe, row_offset, valid_count * sizeof(uint32_t)))
    return;

  // Walk all the bits first because we need to know the number of rows for
  // some tables in order to parse others. In particular this applies to
  // coded indexes, which are documented in ECMA-335 II.24.2.6.
  for (bit_check = 0; bit_check < 64; bit_check++)
  {
    if (!((yr_le64toh(tilde_header->Valid) >> bit_check) & 0x01))
      continue;

#define ROW_CHECK(name)                                              \
  if ((uint8_t*)(row_offset + matched_bits + 1) <= tilde_stream_end) \
    rows.name = *(row_offset + matched_bits);

#define ROW_CHECK_WITH_INDEX(name)    \
  ROW_CHECK(name);                    \
  if (yr_le32toh(rows.name) > 0xFFFF) \
    index_sizes.name = 4;

    switch (bit_check)
    {
    case BIT_MODULE:
      ROW_CHECK_WITH_INDEX(module);
      break;
    case BIT_MODULEREF:
      ROW_CHECK_WITH_INDEX(moduleref);
      break;
    case BIT_ASSEMBLYREF:
      ROW_CHECK_WITH_INDEX(assemblyref);
      break;
    case BIT_ASSEMBLYREFPROCESSOR:
      ROW_CHECK_WITH_INDEX(assemblyrefprocessor);
      break;
    case BIT_TYPEREF:
      ROW_CHECK_WITH_INDEX(typeref);
      break;
    case BIT_METHODDEF:
      ROW_CHECK_WITH_INDEX(methoddef);
      break;
    case BIT_MEMBERREF:
      ROW_CHECK_WITH_INDEX(memberref);
      break;
    case BIT_TYPEDEF:
      ROW_CHECK_WITH_INDEX(typedef_);
      break;
    case BIT_TYPESPEC:
      ROW_CHECK_WITH_INDEX(typespec);
      break;
    case BIT_FIELD:
      ROW_CHECK_WITH_INDEX(field);
      break;
    case BIT_PARAM:
      ROW_CHECK_WITH_INDEX(param);
      break;
    case BIT_PROPERTY:
      ROW_CHECK_WITH_INDEX(property);
      break;
    case BIT_INTERFACEIMPL:
      ROW_CHECK_WITH_INDEX(interfaceimpl);
      break;
    case BIT_EVENT:
      ROW_CHECK_WITH_INDEX(event);
      break;
    case BIT_STANDALONESIG:
      ROW_CHECK(standalonesig);
      break;
    case BIT_ASSEMBLY:
      ROW_CHECK_WITH_INDEX(assembly);
      break;
    case BIT_FILE:
      ROW_CHECK(file);
      break;
    case BIT_EXPORTEDTYPE:
      ROW_CHECK(exportedtype);
      break;
    case BIT_MANIFESTRESOURCE:
      ROW_CHECK(manifestresource);
      break;
    case BIT_GENERICPARAM:
      ROW_CHECK_WITH_INDEX(genericparam);
      break;
    case BIT_GENERICPARAMCONSTRAINT:
      ROW_CHECK(genericparamconstraint);
      break;
    case BIT_METHODSPEC:
      ROW_CHECK_WITH_INDEX(methodspec);
      break;
    default:
      break;
    }

    matched_bits++;
  }

  // This is used when parsing the MANIFEST RESOURCE table.
  resource_base = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->Resources.VirtualAddress));

  dotnet_parse_tilde_2(
      pe, tilde_header, resource_base, rows, index_sizes, streams);
}

static bool dotnet_is_dotnet(PE* pe)
{
  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);

  if (!directory)
    return false;

  int64_t offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0 || !struct_fits_in_pe(pe, pe->data + offset, CLI_HEADER))
    return false;

  CLI_HEADER* cli_header = (CLI_HEADER*) (pe->data + offset);

  if (yr_le32toh(cli_header->Size) != sizeof(CLI_HEADER))
    return false;

  int64_t metadata_root = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->MetaData.VirtualAddress));
  offset = metadata_root;

  if (!struct_fits_in_pe(pe, pe->data + metadata_root, NET_METADATA))
    return false;

  NET_METADATA* metadata = (NET_METADATA*) (pe->data + metadata_root);

  if (yr_le32toh(metadata->Magic) != NET_METADATA_MAGIC)
    return false;

  // Version length must be between 1 and 255, and be a multiple of 4.
  // Also make sure it fits in pe.
  uint32_t md_len = yr_le32toh(metadata->Length);
  if (md_len == 0 || md_len > 255 || md_len % 4 != 0 ||
      !fits_in_pe(pe, pe->data + offset + sizeof(NET_METADATA), md_len))
  {
    return false;
  }

  if (IS_64BITS_PE(pe))
  {
    if (yr_le32toh(OptionalHeader(pe, NumberOfRvaAndSizes)) <
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
      return false;
  }

  return true;
}

void dotnet_parse_com(PE* pe)
{
  PIMAGE_DATA_DIRECTORY directory;
  PCLI_HEADER cli_header;
  PNET_METADATA metadata;
  int64_t metadata_root, offset;
  char* end;
  STREAMS headers;
  WORD num_streams;
  uint32_t md_len;

  if (!dotnet_is_dotnet(pe))
  {
    yr_set_integer(0, pe->object, "is_dotnet");
    return;
  }

  yr_set_integer(1, pe->object, "is_dotnet");

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
  if (directory == NULL)
    return;

  offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0 || !struct_fits_in_pe(pe, pe->data + offset, CLI_HEADER))
    return;

  cli_header = (PCLI_HEADER) (pe->data + offset);

  offset = metadata_root = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->MetaData.VirtualAddress));

  if (!struct_fits_in_pe(pe, pe->data + offset, NET_METADATA))
    return;

  metadata = (PNET_METADATA) (pe->data + offset);

  // Version length must be between 1 and 255, and be a multiple of 4.
  // Also make sure it fits in pe.
  md_len = yr_le32toh(metadata->Length);

  if (md_len == 0 || md_len > 255 || md_len % 4 != 0 ||
      !fits_in_pe(pe, pe->data + offset + sizeof(NET_METADATA), md_len))
  {
    return;
  }

  // The length includes the NULL terminator and is rounded up to a multiple of
  // 4. We need to exclude the terminator and the padding, so search for the
  // first NULL byte.
  end = (char*) memmem((void*) metadata->Version, md_len, "\0", 1);

  if (end != NULL)
    yr_set_sized_string(
        metadata->Version, (end - metadata->Version), pe->object, "version");

  // The metadata structure has some variable length records after the version.
  // We must manually parse things from here on out.
  //
  // Flags are 2 bytes (always 0).
  offset += sizeof(NET_METADATA) + md_len + 2;

  // 2 bytes for Streams.
  if (!fits_in_pe(pe, pe->data + offset, 2))
    return;

  num_streams = (WORD) * (pe->data + offset);
  offset += 2;

  headers = dotnet_parse_stream_headers(pe, offset, metadata_root, num_streams);

  if (headers.guid != NULL)
    dotnet_parse_guid(pe, metadata_root, headers.guid);

  // Parse the #~ stream, which includes various tables of interest.
  // These tables reference the blob and string streams, so we need to ensure
  // those are not NULL also.
  if (headers.tilde != NULL && headers.string != NULL && headers.blob != NULL)
    dotnet_parse_tilde(pe, cli_header, &headers);

  if (headers.us != NULL)
    dotnet_parse_us(pe, metadata_root, headers.us);
}

typedef enum
{
  DOTNET_PATTERN_OPCODE = 0,
  DOTNET_PATTERN_ANY,
  DOTNET_PATTERN_GAP
} DOTNET_PATTERN_TYPE;

typedef struct
{
  uint16_t opcode;
  DOTNET_PATTERN_TYPE type;
} DOTNET_PATTERN;

static bool dotnet_name_equals(const char* name, const char* token, size_t len)
{
  size_t name_len = strlen(name);

  if (name_len != len)
    return false;

  for (size_t i = 0; i < len; i++)
  {
    if (tolower((unsigned char) name[i]) != tolower((unsigned char) token[i]))
      return false;
  }

  return true;
}

static bool dotnet_parse_opcode_token(
    const char* token,
    size_t len,
    uint16_t* opcode)
{
  char buffer[64];

  if (len == 0 || len >= sizeof(buffer))
    return false;

  memcpy(buffer, token, len);
  buffer[len] = '\0';

  if (isdigit((unsigned char) buffer[0]) ||
      (buffer[0] == '0' && len > 1 &&
       (buffer[1] == 'x' || buffer[1] == 'X')))
  {
    char* end = NULL;
    int base = (buffer[0] == '0' && len > 1 &&
                (buffer[1] == 'x' || buffer[1] == 'X'))
                   ? 16
                   : 10;
    unsigned long value = strtoul(buffer, &end, base);

    if (end == buffer || *end != '\0' || value > 0xffff)
      return false;

    *opcode = (uint16_t) value;
    return true;
  }

  for (size_t i = 0; i < sizeof(dotnet_opcodes) / sizeof(dotnet_opcodes[0]); i++)
  {
    if (dotnet_name_equals(dotnet_opcodes[i].name, token, len))
    {
      *opcode = dotnet_opcodes[i].opcode;
      return true;
    }
  }

  return false;
}

static bool dotnet_parse_opcode_pattern(
    const SIZED_STRING* pattern,
    DOTNET_PATTERN* result,
    uint32_t* result_len)
{
  const char* text = pattern->c_string;
  size_t len = pattern->length;
  size_t offset = 0;
  uint32_t count = 0;

  while (offset < len)
  {
    while (offset < len &&
           (isspace((unsigned char) text[offset]) || text[offset] == ','))
      offset++;

    if (offset >= len)
      break;

    size_t start = offset;

    while (offset < len && !isspace((unsigned char) text[offset]) &&
           text[offset] != ',')
      offset++;

    size_t token_len = offset - start;
    const char* token = text + start;

    if (count >= DOTNET_MAX_PATTERN_TOKENS)
      return false;

    if ((token_len == 1 && token[0] == '?') ||
        (token_len == 2 && token[0] == '?' && token[1] == '?'))
    {
      result[count].type = DOTNET_PATTERN_ANY;
      result[count].opcode = 0;
    }
    else if ((token_len == 1 && token[0] == '*') ||
             (token_len == 3 && token[0] == '.' && token[1] == '.' &&
              token[2] == '.'))
    {
      result[count].type = DOTNET_PATTERN_GAP;
      result[count].opcode = 0;
    }
    else
    {
      result[count].type = DOTNET_PATTERN_OPCODE;

      if (!dotnet_parse_opcode_token(token, token_len, &result[count].opcode))
        return false;
    }

    count++;
  }

  *result_len = count;
  return count > 0;
}

static bool dotnet_match_from(
    const uint16_t* opcodes,
    uint32_t opcode_count,
    const DOTNET_PATTERN* pattern,
    uint32_t pattern_count)
{
  uint32_t i = 0;
  uint32_t j = 0;
  int64_t gap_pattern = -1;
  uint32_t gap_opcode = 0;

  while (i < opcode_count)
  {
    if (j == pattern_count)
      return true;

    if (j < pattern_count &&
        (pattern[j].type == DOTNET_PATTERN_ANY ||
         (pattern[j].type == DOTNET_PATTERN_OPCODE &&
          pattern[j].opcode == opcodes[i])))
    {
      i++;
      j++;
    }
    else if (j < pattern_count && pattern[j].type == DOTNET_PATTERN_GAP)
    {
      gap_pattern = j++;
      gap_opcode = i;
    }
    else if (gap_pattern >= 0)
    {
      j = (uint32_t) gap_pattern + 1;
      i = ++gap_opcode;
    }
    else
    {
      return false;
    }
  }

  while (j < pattern_count && pattern[j].type == DOTNET_PATTERN_GAP)
    j++;

  return j == pattern_count;
}

static bool dotnet_match_sequence(
    const uint16_t* opcodes,
    uint32_t opcode_count,
    const DOTNET_PATTERN* pattern,
    uint32_t pattern_count)
{
  if (pattern_count == 0)
    return false;

  if (opcode_count == 0)
  {
    for (uint32_t i = 0; i < pattern_count; i++)
    {
      if (pattern[i].type != DOTNET_PATTERN_GAP)
        return false;
    }

    return true;
  }

  for (uint32_t start = 0; start < opcode_count; start++)
  {
    if (dotnet_match_from(
            opcodes + start, opcode_count - start, pattern, pattern_count))
      return true;
  }

  return false;
}

static bool dotnet_sized_string_equals(
    const SIZED_STRING* value,
    const char* text,
    size_t len)
{
  return value != NULL && value->length == len &&
         memcmp(value->c_string, text, len) == 0;
}

static bool dotnet_method_selected(
    YR_OBJECT* module,
    int class_idx,
    int method_idx,
    const SIZED_STRING* selector)
{
  if (selector == NULL || selector->length == 0)
    return true;

  SIZED_STRING* method_name = yr_get_string(
      module,
      "classes[%i].methods[%i].name",
      class_idx,
      method_idx);

  if (method_name == NULL)
    return false;

  const char* text = selector->c_string;
  size_t len = selector->length;
  const char* separator = NULL;
  size_t separator_len = 0;

  for (size_t i = 0; i + 1 < len; i++)
  {
    if (text[i] == ':' && text[i + 1] == ':')
    {
      separator = text + i;
      separator_len = 2;
      break;
    }
  }

  if (separator == NULL && len > 1 && text[0] != '.')
  {
    for (size_t i = len; i > 0; i--)
    {
      if (text[i - 1] == '.')
      {
        separator = text + i - 1;
        separator_len = 1;
        break;
      }
    }
  }

  if (separator == NULL)
    return dotnet_sized_string_equals(method_name, text, len);

  size_t class_len = separator - text;
  size_t method_offset = class_len + separator_len;

  if (method_offset >= len)
    return false;

  if (!dotnet_sized_string_equals(
          method_name, text + method_offset, len - method_offset))
    return false;

  SIZED_STRING* class_name = yr_get_string(
      module, "classes[%i].fullname", class_idx);

  return dotnet_sized_string_equals(class_name, text, class_len);
}

static bool dotnet_sequence_in_module(
    YR_OBJECT* module,
    const SIZED_STRING* selector,
    int class_index,
    int method_index,
    const DOTNET_PATTERN* pattern,
    uint32_t pattern_count)
{
  int64_t class_count = yr_get_integer(module, "number_of_classes");

  if (class_count <= 0)
    return false;

  int class_start = class_index < 0 ? 0 : class_index;
  int class_end = class_index < 0 ? (int) class_count : class_index + 1;

  if (class_start >= class_count)
    return false;

  for (int class_idx = class_start; class_idx < class_end; class_idx++)
  {
    int64_t method_count = yr_get_integer(
        module, "classes[%i].number_of_methods", class_idx);

    if (method_count <= 0)
      continue;

    int method_start = method_index < 0 ? 0 : method_index;
    int method_end = method_index < 0 ? (int) method_count : method_index + 1;

    if (method_start >= method_count)
      continue;

    for (int method_idx = method_start; method_idx < method_end; method_idx++)
    {
      if (selector != NULL &&
          !dotnet_method_selected(module, class_idx, method_idx, selector))
        continue;

      int64_t opcode_count = yr_get_integer(
          module,
          "classes[%i].methods[%i].number_of_opcodes",
          class_idx,
          method_idx);

      if (opcode_count <= 0 ||
          opcode_count > DOTNET_MAX_IL_INSTRUCTIONS)
        continue;

      uint16_t* opcodes = (uint16_t*) yr_malloc(
          (size_t) opcode_count * sizeof(uint16_t));

      if (opcodes == NULL)
        return false;

      for (int64_t i = 0; i < opcode_count; i++)
      {
        opcodes[i] = (uint16_t) yr_get_integer(
            module,
            "classes[%i].methods[%i].opcodes[%i]",
            class_idx,
            method_idx,
            (int) i);
      }

      bool match = dotnet_match_sequence(
          opcodes, (uint32_t) opcode_count, pattern, pattern_count);

      yr_free(opcodes);

      if (match)
        return true;
    }
  }

  return false;
}

define_function(dotnet_fn_opcode_sequence)
{
  SIZED_STRING* pattern_text = sized_string_argument(1);
  DOTNET_PATTERN pattern[DOTNET_MAX_PATTERN_TOKENS];
  uint32_t pattern_count = 0;

  if (!dotnet_parse_opcode_pattern(
          pattern_text, pattern, &pattern_count))
    return_integer(0);

  return_integer(dotnet_sequence_in_module(
      yr_module(), NULL, -1, -1, pattern, pattern_count));
}

define_function(dotnet_fn_opcode_sequence_method)
{
  SIZED_STRING* selector = sized_string_argument(1);
  SIZED_STRING* pattern_text = sized_string_argument(2);
  DOTNET_PATTERN pattern[DOTNET_MAX_PATTERN_TOKENS];
  uint32_t pattern_count = 0;

  if (!dotnet_parse_opcode_pattern(
          pattern_text, pattern, &pattern_count))
    return_integer(0);

  return_integer(dotnet_sequence_in_module(
      yr_module(), selector, -1, -1, pattern, pattern_count));
}

define_function(dotnet_fn_opcode_sequence_indexed)
{
  int64_t class_index = integer_argument(1);
  int64_t method_index = integer_argument(2);
  SIZED_STRING* pattern_text = sized_string_argument(3);
  DOTNET_PATTERN pattern[DOTNET_MAX_PATTERN_TOKENS];
  uint32_t pattern_count = 0;

  if (class_index < 0 || method_index < 0 ||
      !dotnet_parse_opcode_pattern(
          pattern_text, pattern, &pattern_count))
    return_integer(0);

  return_integer(dotnet_sequence_in_module(
      yr_module(),
      NULL,
      (int) class_index,
      (int) method_index,
      pattern,
      pattern_count));
}

static bool dotnet_numeric_opcode_sequence(
    YR_VALUE* args,
    YR_OBJECT_FUNCTION* function_obj,
    int argument_count)
{
  DOTNET_PATTERN pattern[8];

  for (int i = 0; i < argument_count; i++)
  {
    if (args[i].i < 0 || args[i].i > 0xffff)
      return false;

    pattern[i].type = DOTNET_PATTERN_OPCODE;
    pattern[i].opcode = (uint16_t) args[i].i;
  }

  return dotnet_sequence_in_module(
      yr_object_get_root((YR_OBJECT*) function_obj),
      NULL,
      -1,
      -1,
      pattern,
      (uint32_t) argument_count);
}

define_function(dotnet_fn_opcode_sequence_1)
{
  return_integer(
      dotnet_numeric_opcode_sequence(__args, __function_obj, 1) ? 1 : 0);
}

define_function(dotnet_fn_opcode_sequence_2)
{
  return_integer(
      dotnet_numeric_opcode_sequence(__args, __function_obj, 2) ? 1 : 0);
}

define_function(dotnet_fn_opcode_sequence_3)
{
  return_integer(
      dotnet_numeric_opcode_sequence(__args, __function_obj, 3) ? 1 : 0);
}

define_function(dotnet_fn_opcode_sequence_4)
{
  return_integer(
      dotnet_numeric_opcode_sequence(__args, __function_obj, 4) ? 1 : 0);
}

define_function(dotnet_fn_opcode_sequence_5)
{
  return_integer(
      dotnet_numeric_opcode_sequence(__args, __function_obj, 5) ? 1 : 0);
}

define_function(dotnet_fn_opcode_sequence_6)
{
  return_integer(
      dotnet_numeric_opcode_sequence(__args, __function_obj, 6) ? 1 : 0);
}

define_function(dotnet_fn_opcode_sequence_7)
{
  return_integer(
      dotnet_numeric_opcode_sequence(__args, __function_obj, 7) ? 1 : 0);
}

define_function(dotnet_fn_opcode_sequence_8)
{
  return_integer(
      dotnet_numeric_opcode_sequence(__args, __function_obj, 8) ? 1 : 0);
}

begin_declarations
  declare_integer("is_dotnet");
  declare_string("version");
  declare_string("module_name");

  begin_struct_array("streams")
    declare_string("name");
    declare_integer("offset");
    declare_integer("size");
  end_struct_array("streams")

  declare_integer("number_of_streams");

  declare_string_array("guids");
  declare_integer("number_of_guids");

  begin_struct_array("resources")
    declare_integer("offset");
    declare_integer("length");
    declare_string("name");
  end_struct_array("resources")

  declare_integer("number_of_resources");

  begin_struct_array("classes")
    declare_string("fullname");
    declare_string("name");
    declare_string("namespace");
    declare_string("visibility");
    declare_string("type");
    declare_integer("abstract");
    declare_integer("sealed");

    declare_integer("number_of_generic_parameters");
    declare_string_array("generic_parameters");

    declare_integer("number_of_base_types");
    declare_string_array("base_types");

    declare_integer("number_of_methods");
    begin_struct_array("methods")
      declare_string_array("generic_parameters");

      declare_integer("number_of_generic_parameters");

      begin_struct_array("parameters")
        declare_string("name");
        declare_string("type");
      end_struct_array("parameters")

      declare_integer("number_of_parameters");

      declare_string("return_type");
      declare_integer("abstract");
      declare_integer("final");
      declare_integer("virtual");
      declare_integer("static");
      declare_string("visibility");
      declare_string("name");

      declare_integer("has_body");
      declare_integer("is_tiny");
      declare_integer("is_fat");
      declare_string("format");
      declare_integer("rva");
      declare_integer("offset");
      declare_integer("body_size");
      declare_integer("size");
      declare_integer("header_size");
      declare_integer("code_offset");
      declare_integer("code_size");
      declare_integer("max_stack");
      declare_integer("local_var_sig_tok");
      declare_integer("local_var_sig_token");
      declare_integer("flags");
      declare_integer("init_locals");

      declare_integer("number_of_instructions");
      declare_integer("instruction_count");
      begin_struct_array("instructions")
        declare_integer("offset");
        declare_integer("il_offset");
        declare_integer("file_offset");
        declare_integer("rva");
        declare_integer("address");
        declare_integer("opcode");
        declare_integer("opcode_size");
        declare_string("opcode_name");
        declare_string("mnemonic");
        declare_string("name");
        declare_integer("operand");
        declare_integer("operand_size");
        declare_integer("size");
        declare_integer("branch_target");
        declare_integer("number_of_switch_targets");
        declare_integer_array("switch_targets");
      end_struct_array("instructions")

      declare_integer("number_of_opcodes");
      declare_integer_array("opcodes");

      declare_integer("number_of_exception_handlers");
      declare_integer("exception_handler_count");
      begin_struct_array("exception_handlers")
        declare_integer("offset");
        declare_integer("flags");
        declare_string("type");
        declare_string("handler_type");
        declare_integer("try_offset");
        declare_integer("try_start");
        declare_integer("try_length");
        declare_integer("try_end");
        declare_integer("handler_offset");
        declare_integer("handler_start");
        declare_integer("handler_length");
        declare_integer("handler_end");
        declare_integer("class_token");
        declare_integer("catch_type");
        declare_integer("catch_type_token");
        declare_integer("filter_offset");
        declare_integer("filter_start");
        declare_integer("exception_type");
      end_struct_array("exception_handlers")

      declare_integer("number_of_exception_regions");
      begin_struct_array("exception_regions")
        declare_integer("offset");
        declare_integer("flags");
        declare_string("type");
        declare_string("handler_type");
        declare_integer("try_offset");
        declare_integer("try_start");
        declare_integer("try_length");
        declare_integer("try_end");
        declare_integer("handler_offset");
        declare_integer("handler_start");
        declare_integer("handler_length");
        declare_integer("handler_end");
        declare_integer("class_token");
        declare_integer("catch_type");
        declare_integer("catch_type_token");
        declare_integer("filter_offset");
        declare_integer("filter_start");
        declare_integer("exception_type");
      end_struct_array("exception_regions")
    end_struct_array("methods")

  end_struct_array("classes")

  declare_integer("number_of_classes");

  begin_struct_array("assembly_refs")
    begin_struct("version")
      declare_integer("major");
      declare_integer("minor");
      declare_integer("build_number");
      declare_integer("revision_number");
    end_struct("version")
    declare_string("public_key_or_token");
    declare_string("name");
  end_struct_array("assembly_refs")

  declare_integer("number_of_assembly_refs");

  begin_struct("assembly")
    begin_struct("version")
      declare_integer("major");
      declare_integer("minor");
      declare_integer("build_number");
      declare_integer("revision_number");
    end_struct("version")
    declare_string("name");
    declare_string("culture");
  end_struct("assembly")

  declare_string_array("modulerefs");
  declare_integer("number_of_modulerefs");
  declare_string_array("user_strings");
  declare_integer("number_of_user_strings");
  declare_string("typelib");
  declare_string_array("constants");
  declare_integer("number_of_constants");

  declare_integer_array("field_offsets");
  declare_integer("number_of_field_offsets");

  declare_function("opcode_sequence", "s", "i", dotnet_fn_opcode_sequence);
  declare_function(
      "opcode_sequence", "ss", "i", dotnet_fn_opcode_sequence_method);
  declare_function(
      "opcode_sequence", "iis", "i", dotnet_fn_opcode_sequence_indexed);
  declare_function("opcode_sequence", "i", "i", dotnet_fn_opcode_sequence_1);
  declare_function("opcode_sequence", "ii", "i", dotnet_fn_opcode_sequence_2);
  declare_function("opcode_sequence", "iii", "i", dotnet_fn_opcode_sequence_3);
  declare_function(
      "opcode_sequence", "iiii", "i", dotnet_fn_opcode_sequence_4);
  declare_function(
      "opcode_sequence", "iiiii", "i", dotnet_fn_opcode_sequence_5);
  declare_function(
      "opcode_sequence", "iiiiii", "i", dotnet_fn_opcode_sequence_6);
  declare_function(
      "opcode_sequence", "iiiiiii", "i", dotnet_fn_opcode_sequence_7);
  declare_function(
      "opcode_sequence", "iiiiiiii", "i", dotnet_fn_opcode_sequence_8);

  declare_function(
      "il_opcode_sequence", "s", "i", dotnet_fn_opcode_sequence);
  declare_function(
      "il_opcode_sequence", "ss", "i", dotnet_fn_opcode_sequence_method);
  declare_function(
      "il_opcode_sequence", "iis", "i", dotnet_fn_opcode_sequence_indexed);
  declare_function(
      "il_opcode_sequence", "ii", "i", dotnet_fn_opcode_sequence_2);
  declare_function(
      "il_opcode_sequence", "iii", "i", dotnet_fn_opcode_sequence_3);
end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
  const uint8_t* block_data = NULL;

  foreach_memory_block(iterator, block)
  {
    PIMAGE_NT_HEADERS32 pe_header;

    block_data = yr_fetch_block_data(block);

    if (block_data == NULL)
      continue;

    pe_header = pe_get_header(block_data, block->size);

    if (pe_header != NULL)
    {
      // Ignore DLLs while scanning a process

      if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
          !(pe_header->FileHeader.Characteristics & IMAGE_FILE_DLL))
      {
        PE* pe = (PE*) yr_malloc(sizeof(PE));

        if (pe == NULL)
          return ERROR_INSUFFICIENT_MEMORY;

        pe->data = block_data;
        pe->data_size = block->size;
        pe->object = module_object;
        pe->header = pe_header;

        module_object->data = pe;

        dotnet_parse_com(pe);

        break;
      }
    }
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  PE* pe = (PE*) module_object->data;

  if (pe == NULL)
    return ERROR_SUCCESS;

  yr_free(pe);

  return ERROR_SUCCESS;
}
