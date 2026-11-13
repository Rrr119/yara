#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include <yara/endian.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/unaligned.h>

#define MODULE_NAME zip

#define ZIP_EOCD_SIGNATURE             0x06054b50u
#define ZIP64_EOCD_SIGNATURE           0x06064b50u
#define ZIP64_LOCATOR_SIGNATURE        0x07064b50u
#define ZIP_CENTRAL_HEADER_SIGNATURE   0x02014b50u
#define ZIP_LOCAL_HEADER_SIGNATURE     0x04034b50u

#define ZIP_EOCD_MIN_SIZE              22u
#define ZIP64_EOCD_MIN_SIZE            56u
#define ZIP64_LOCATOR_SIZE             20u
#define ZIP_CENTRAL_HEADER_MIN_SIZE    46u
#define ZIP_LOCAL_HEADER_MIN_SIZE      30u
#define ZIP_MAX_COMMENT_SIZE           65535u

#define ZIP_FLAG_ENCRYPTED             0x0001u

#define ZIP_METHOD_STORED              0u
#define ZIP_METHOD_DEFLATED            8u

#define ZIP_MAX_NESTING_DEPTH          8
#define ZIP_MAX_ENTRIES                1000000ULL
#define ZIP_MAX_NESTED_ENTRY_SIZE      (32ULL * 1024ULL * 1024ULL)
#define ZIP_NESTED_SCAN_BUDGET         (64ULL * 1024ULL * 1024ULL)

typedef struct
{
  char* name;
  size_t name_length;
  uint16_t flags;
  uint16_t method;
  uint64_t compressed_size;
  uint64_t uncompressed_size;
  uint64_t local_header_offset;
} ZIP_ENTRY;

typedef struct
{
  ZIP_ENTRY* entries;
  size_t entries_count;
  uint64_t uncompressed_size;
  uint64_t compressed_size;
  double max_ratio;
  int is_encrypted;
  int has_traversal;
  int64_t base_offset;
} ZIP_ARCHIVE;

typedef struct
{
  ZIP_ENTRY* entries;
  size_t entries_count;
} ZIP_MODULE_DATA;

typedef struct
{
  uint64_t remaining;
} ZIP_NESTED_CONTEXT;

static uint16_t zip_read_u16(const uint8_t* data)
{
  return yr_le16toh(yr_unaligned_u16(data));
}

static uint32_t zip_read_u32(const uint8_t* data)
{
  return yr_le32toh(yr_unaligned_u32(data));
}

static uint64_t zip_read_u64(const uint8_t* data)
{
  return yr_le64toh(yr_unaligned_u64(data));
}

static void zip_free_archive(ZIP_ARCHIVE* archive)
{
  if (archive->entries == NULL)
    return;

  for (size_t i = 0; i < archive->entries_count; i++)
    yr_free(archive->entries[i].name);

  yr_free(archive->entries);
  archive->entries = NULL;
  archive->entries_count = 0;
}

static bool zip_name_has_traversal(const char* name, size_t length)
{
  if (length == 0)
    return false;

  if (name[0] == '/' || name[0] == '\\')
    return true;

  if (length >= 2 && isalpha((unsigned char) name[0]) && name[1] == ':')
    return true;

  size_t component_start = 0;

  for (size_t i = 0; i <= length; i++)
  {
    if (i < length && name[i] != '/' && name[i] != '\\')
      continue;

    size_t component_length = i - component_start;

    if (component_length == 2 &&
        name[component_start] == '.' &&
        name[component_start + 1] == '.')
    {
      return true;
    }

    component_start = i + 1;
  }

  return false;
}

static bool zip_parse_zip64_extra(
    const uint8_t* extra,
    uint16_t extra_length,
    bool need_uncompressed_size,
    bool need_compressed_size,
    bool need_local_header_offset,
    bool need_disk_number,
    uint64_t* uncompressed_size,
    uint64_t* compressed_size,
    uint64_t* local_header_offset)
{
  size_t offset = 0;

  while (offset + 4 <= extra_length)
  {
    uint16_t field_id = zip_read_u16(extra + offset);
    uint16_t field_length = zip_read_u16(extra + offset + 2);
    size_t field_start = offset + 4;
    size_t field_end = field_start + field_length;
    size_t field_offset = field_start;

    if (field_end > extra_length)
      return false;

    if (field_id == 0x0001)
    {
      if (need_uncompressed_size)
      {
        if (field_offset + 8 > field_end)
          return false;

        *uncompressed_size = zip_read_u64(extra + field_offset);
        field_offset += 8;
      }

      if (need_compressed_size)
      {
        if (field_offset + 8 > field_end)
          return false;

        *compressed_size = zip_read_u64(extra + field_offset);
        field_offset += 8;
      }

      if (need_local_header_offset)
      {
        if (field_offset + 8 > field_end)
          return false;

        *local_header_offset = zip_read_u64(extra + field_offset);
        field_offset += 8;
      }

      if (need_disk_number)
      {
        if (field_offset + 4 > field_end)
          return false;
      }

      return true;
    }

    offset = field_end;
  }

  return !need_uncompressed_size &&
         !need_compressed_size &&
         !need_local_header_offset &&
         !need_disk_number;
}

static bool zip_parse_zip64_eocd(
    const uint8_t* data,
    size_t data_size,
    size_t eocd_offset,
    uint64_t* entries,
    uint64_t* central_directory_size,
    uint64_t* central_directory_offset,
    size_t* zip64_eocd_offset)
{
  if (eocd_offset < ZIP64_LOCATOR_SIZE)
    return false;

  size_t locator_offset = eocd_offset - ZIP64_LOCATOR_SIZE;

  if (zip_read_u32(data + locator_offset) != ZIP64_LOCATOR_SIGNATURE)
    return false;

  uint64_t record_offset = zip_read_u64(data + locator_offset + 8);

  if (record_offset > data_size ||
      data_size - (size_t) record_offset < ZIP64_EOCD_MIN_SIZE)
  {
    return false;
  }

  const uint8_t* record = data + record_offset;

  if (zip_read_u32(record) != ZIP64_EOCD_SIGNATURE)
    return false;

  uint64_t record_size = zip_read_u64(record + 4);

  if (record_size < 44 ||
      record_size > data_size - (size_t) record_offset - 12)
  {
    return false;
  }

  *entries = zip_read_u64(record + 32);
  *central_directory_size = zip_read_u64(record + 40);
  *central_directory_offset = zip_read_u64(record + 48);
  *zip64_eocd_offset = (size_t) record_offset;

  return true;
}

static bool zip_parse_central_directory(
    const uint8_t* data,
    size_t data_size,
    uint64_t entries_count,
    uint64_t central_directory_size,
    uint64_t central_directory_offset,
    ZIP_ARCHIVE* archive)
{
  if (central_directory_offset > data_size ||
      central_directory_size > data_size - (size_t) central_directory_offset)
  {
    return false;
  }

  if (entries_count > central_directory_size / ZIP_CENTRAL_HEADER_MIN_SIZE)
    return false;

  if (entries_count > ZIP_MAX_ENTRIES)
    return false;

  if (entries_count > SIZE_MAX / sizeof(ZIP_ENTRY))
    return false;

  if (entries_count > 0)
  {
    archive->entries = (ZIP_ENTRY*) yr_calloc((size_t) entries_count, sizeof(ZIP_ENTRY));

    if (archive->entries == NULL)
      return false;
  }

  archive->entries_count = (size_t) entries_count;

  size_t offset = (size_t) central_directory_offset;

  for (size_t i = 0; i < archive->entries_count; i++)
  {
    if (offset > data_size || data_size - offset < ZIP_CENTRAL_HEADER_MIN_SIZE)
      return false;

    if (zip_read_u32(data + offset) != ZIP_CENTRAL_HEADER_SIGNATURE)
      return false;

    uint16_t name_length = zip_read_u16(data + offset + 28);
    uint16_t extra_length = zip_read_u16(data + offset + 30);
    uint16_t comment_length = zip_read_u16(data + offset + 32);
    size_t record_size =
        ZIP_CENTRAL_HEADER_MIN_SIZE + name_length + extra_length + comment_length;

    if (record_size > central_directory_size - (offset - (size_t) central_directory_offset) ||
        record_size > data_size - offset)
    {
      return false;
    }

    ZIP_ENTRY* entry = &archive->entries[i];

    entry->flags = zip_read_u16(data + offset + 8);
    entry->method = zip_read_u16(data + offset + 10);
    entry->compressed_size = zip_read_u32(data + offset + 20);
    entry->uncompressed_size = zip_read_u32(data + offset + 24);
    entry->local_header_offset = zip_read_u32(data + offset + 42);

    uint16_t disk_number = zip_read_u16(data + offset + 34);
    const uint8_t* extra = data + offset + ZIP_CENTRAL_HEADER_MIN_SIZE + name_length;

    if (entry->compressed_size == UINT32_MAX ||
        entry->uncompressed_size == UINT32_MAX ||
        entry->local_header_offset == UINT32_MAX ||
        disk_number == UINT16_MAX)
    {
      if (!zip_parse_zip64_extra(
              extra,
              extra_length,
              entry->uncompressed_size == UINT32_MAX,
              entry->compressed_size == UINT32_MAX,
              entry->local_header_offset == UINT32_MAX,
              disk_number == UINT16_MAX,
              &entry->uncompressed_size,
              &entry->compressed_size,
              &entry->local_header_offset))
      {
        return false;
      }
    }

    if (entry->flags & ZIP_FLAG_ENCRYPTED)
      archive->is_encrypted = 1;

    if (entry->uncompressed_size > UINT64_MAX - archive->uncompressed_size ||
        entry->compressed_size > UINT64_MAX - archive->compressed_size)
    {
      return false;
    }

    archive->uncompressed_size += entry->uncompressed_size;
    archive->compressed_size += entry->compressed_size;

    if (archive->uncompressed_size > INT64_MAX ||
        archive->compressed_size > INT64_MAX)
    {
      return false;
    }

    double ratio;

    if (entry->compressed_size == 0)
      ratio = entry->uncompressed_size == 0
                  ? 0.0
                  : (double) entry->uncompressed_size;
    else
      ratio = (double) entry->uncompressed_size /
              (double) entry->compressed_size;

    if (ratio > archive->max_ratio)
      archive->max_ratio = ratio;

    entry->name = yr_malloc(name_length + 1);

    if (entry->name == NULL)
      return false;

    memcpy(entry->name, data + offset + ZIP_CENTRAL_HEADER_MIN_SIZE, name_length);
    entry->name[name_length] = '\0';
    entry->name_length = name_length;

    if (zip_name_has_traversal(entry->name, entry->name_length))
      archive->has_traversal = 1;

    offset += record_size;
  }

  return true;
}

static int zip_parse(
    const uint8_t* data,
    size_t data_size,
    ZIP_ARCHIVE* archive)
{
  memset(archive, 0, sizeof(ZIP_ARCHIVE));

  if (data_size < ZIP_EOCD_MIN_SIZE)
    return 0;

  size_t first_possible_eocd = data_size > ZIP_EOCD_MIN_SIZE + ZIP_MAX_COMMENT_SIZE
                                   ? data_size - ZIP_EOCD_MIN_SIZE - ZIP_MAX_COMMENT_SIZE
                                   : 0;

  for (size_t eocd_offset = data_size - ZIP_EOCD_MIN_SIZE;; eocd_offset--)
  {
    if (zip_read_u32(data + eocd_offset) == ZIP_EOCD_SIGNATURE)
    {
      uint16_t comment_length = zip_read_u16(data + eocd_offset + 20);

      if (comment_length <= data_size - eocd_offset - ZIP_EOCD_MIN_SIZE)
      {
        uint64_t entries_count = zip_read_u16(data + eocd_offset + 10);
        uint64_t central_directory_size = zip_read_u32(data + eocd_offset + 12);
        uint64_t central_directory_offset = zip_read_u32(data + eocd_offset + 16);
        size_t zip64_eocd_offset = 0;

        if (entries_count == UINT16_MAX ||
            central_directory_size == UINT32_MAX ||
            central_directory_offset == UINT32_MAX)
        {
          if (!zip_parse_zip64_eocd(
                  data,
                  data_size,
                  eocd_offset,
                  &entries_count,
                  &central_directory_size,
                  &central_directory_offset,
                  &zip64_eocd_offset))
          {
            goto next_eocd;
          }
        }

        uint64_t candidate_offsets[3];
        size_t candidate_count = 0;

        candidate_offsets[candidate_count++] = central_directory_offset;

        if (eocd_offset >= central_directory_size)
        {
          candidate_offsets[candidate_count++] =
              eocd_offset - central_directory_size;
        }

        if (zip64_eocd_offset != 0 && zip64_eocd_offset >= central_directory_size)
        {
          candidate_offsets[candidate_count++] =
              zip64_eocd_offset - central_directory_size;
        }

        for (size_t i = 0; i < candidate_count; i++)
        {
          uint64_t candidate = candidate_offsets[i];

          if (candidate > data_size)
            continue;

          if (zip_parse_central_directory(
                  data,
                  data_size,
                  entries_count,
                  central_directory_size,
                  candidate,
                  archive))
          {
            if (candidate != central_directory_offset)
            {
              archive->base_offset =
                  (int64_t) candidate - (int64_t) central_directory_offset;
            }

            return 1;
          }

          zip_free_archive(archive);
          memset(archive, 0, sizeof(ZIP_ARCHIVE));
        }
      }
    }

next_eocd:
    if (eocd_offset == first_possible_eocd)
      break;
  }

  return 0;
}

static bool zip_get_local_data(
    const uint8_t* data,
    size_t data_size,
    const ZIP_ARCHIVE* archive,
    const ZIP_ENTRY* entry,
    size_t* local_data_offset,
    size_t* local_data_size)
{
  if (data_size > INT64_MAX ||
      entry->local_header_offset > (uint64_t) data_size)
    return false;

  int64_t adjusted_offset;

  if (archive->base_offset >= 0)
  {
    if (entry->local_header_offset >
        (uint64_t) (INT64_MAX - archive->base_offset))
    {
      return false;
    }

    adjusted_offset =
        (int64_t) entry->local_header_offset + archive->base_offset;
  }
  else
  {
    uint64_t base_offset_abs =
        (uint64_t) (-(archive->base_offset + 1)) + 1;

    if (entry->local_header_offset < base_offset_abs)
      return false;

    adjusted_offset =
        (int64_t) (entry->local_header_offset - base_offset_abs);
  }

  if (adjusted_offset < 0 || (uint64_t) adjusted_offset > data_size ||
      data_size - (size_t) adjusted_offset < ZIP_LOCAL_HEADER_MIN_SIZE)
  {
    return false;
  }

  size_t offset = (size_t) adjusted_offset;

  if (zip_read_u32(data + offset) != ZIP_LOCAL_HEADER_SIGNATURE)
    return false;

  uint16_t name_length = zip_read_u16(data + offset + 26);
  uint16_t extra_length = zip_read_u16(data + offset + 28);
  uint64_t header_size =
      ZIP_LOCAL_HEADER_MIN_SIZE + (uint64_t) name_length + extra_length;

  if (header_size > data_size - offset)
    return false;

  *local_data_offset = offset + (size_t) header_size;

  if (entry->compressed_size > data_size - *local_data_offset)
    return false;

  *local_data_size = (size_t) entry->compressed_size;

  return true;
}

static bool zip_inflate_entry(
    const uint8_t* data,
    size_t data_size,
    uint64_t expected_size,
    uint8_t** output)
{
  if (expected_size > ZIP_MAX_NESTED_ENTRY_SIZE ||
      expected_size > UINT_MAX ||
      data_size > UINT_MAX)
  {
    return false;
  }

  size_t output_capacity = (size_t) expected_size + 1;
  uint8_t* buffer = (uint8_t*) yr_malloc(output_capacity);

  if (buffer == NULL)
    return false;

  z_stream stream;
  memset(&stream, 0, sizeof(stream));

  stream.next_in = (uint8_t*) data;
  stream.avail_in = (uInt) data_size;
  stream.next_out = buffer;
  stream.avail_out = (uInt) output_capacity;

  if (inflateInit2(&stream, -MAX_WBITS) != Z_OK)
  {
    yr_free(buffer);
    return false;
  }

  int result;

  do
  {
    result = inflate(&stream, Z_NO_FLUSH);

    if (result == Z_STREAM_END)
      break;

    if (result != Z_OK)
    {
      inflateEnd(&stream);
      yr_free(buffer);
      return false;
    }
  } while (stream.avail_out > 0 && stream.avail_in > 0);

  bool valid =
      result == Z_STREAM_END &&
      stream.total_out == expected_size;

  inflateEnd(&stream);

  if (!valid)
  {
    yr_free(buffer);
    return false;
  }

  *output = buffer;
  return true;
}

static bool zip_get_entry_content(
    const uint8_t* data,
    size_t data_size,
    const ZIP_ARCHIVE* archive,
    const ZIP_ENTRY* entry,
    const uint8_t** content,
    size_t* content_size,
    uint8_t** allocated)
{
  size_t local_data_offset;
  size_t local_data_size;

  *allocated = NULL;

  if (entry->uncompressed_size > ZIP_MAX_NESTED_ENTRY_SIZE ||
      !zip_get_local_data(
          data,
          data_size,
          archive,
          entry,
          &local_data_offset,
          &local_data_size))
  {
    return false;
  }

  if (entry->flags & ZIP_FLAG_ENCRYPTED)
    return false;

  if (entry->method == ZIP_METHOD_STORED)
  {
    if (entry->compressed_size != entry->uncompressed_size)
      return false;

    *content = data + local_data_offset;
    *content_size = local_data_size;
    return true;
  }

  if (entry->method == ZIP_METHOD_DEFLATED)
  {
    uint8_t* output;

    if (!zip_inflate_entry(
            data + local_data_offset,
            local_data_size,
            entry->uncompressed_size,
            &output))
    {
      return false;
    }

    *content = output;
    *content_size = (size_t) entry->uncompressed_size;
    *allocated = output;
    return true;
  }

  return false;
}

static bool zip_measure_nested_depth(
    const uint8_t* data,
    size_t data_size,
    const ZIP_ARCHIVE* archive,
    int depth,
    ZIP_NESTED_CONTEXT* nested_context,
    uint64_t* nested_depth)
{
  if (depth >= ZIP_MAX_NESTING_DEPTH)
    return true;

  for (size_t i = 0; i < archive->entries_count; i++)
  {
    const ZIP_ENTRY* entry = &archive->entries[i];

    if (nested_context->remaining == 0)
      break;

    if (entry->uncompressed_size == 0 ||
        entry->uncompressed_size > nested_context->remaining ||
        entry->uncompressed_size > ZIP_MAX_NESTED_ENTRY_SIZE)
    {
      continue;
    }

    const uint8_t* content;
    size_t content_size;
    uint8_t* allocated;

    if (!zip_get_entry_content(
            data,
            data_size,
            archive,
            entry,
            &content,
            &content_size,
            &allocated))
    {
      continue;
    }

    ZIP_ARCHIVE child_archive;
    int parse_result = zip_parse(content, content_size, &child_archive);

    if (parse_result == 1)
    {
      uint64_t child_depth = 0;

      if (depth + 1 < ZIP_MAX_NESTING_DEPTH)
      {
        if (!zip_measure_nested_depth(
                content,
                content_size,
                &child_archive,
                depth + 1,
                nested_context,
                &child_depth))
        {
          zip_free_archive(&child_archive);
          yr_free(allocated);
          return false;
        }
      }

      if (child_depth + 1 > *nested_depth)
        *nested_depth = child_depth + 1;
    }

    if (parse_result == 1)
      zip_free_archive(&child_archive);

    yr_free(allocated);
    nested_context->remaining -= entry->uncompressed_size;
  }

  return true;
}

define_function(entry_name)
{
  ZIP_MODULE_DATA* zip = (ZIP_MODULE_DATA*) yr_module()->data;
  int64_t index = integer_argument(1);

  if (index == YR_UNDEFINED ||
      zip == NULL ||
      index < 0 ||
      (uint64_t) index >= zip->entries_count)
  {
    return_string(YR_UNDEFINED);
  }

  ZIP_ENTRY* entry = &zip->entries[index];

  return yr_object_set_string(
      entry->name,
      entry->name_length,
      __function_obj->return_obj,
      NULL);
}

begin_declarations
  declare_integer("valid");
  declare_integer("entries");
  declare_integer("uncompressed_size");
  declare_integer("compressed_size");
  declare_float("max_ratio");
  declare_integer("is_encrypted");
  declare_integer("has_traversal");
  declare_integer("nested_depth");
  declare_function("entry_name", "i", "s", entry_name);
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

  module_object->data = NULL;

  yr_set_integer(0, module_object, "valid");
  yr_set_integer(0, module_object, "entries");
  yr_set_integer(0, module_object, "uncompressed_size");
  yr_set_integer(0, module_object, "compressed_size");
  yr_set_float(0.0, module_object, "max_ratio");
  yr_set_integer(0, module_object, "is_encrypted");
  yr_set_integer(0, module_object, "has_traversal");
  yr_set_integer(0, module_object, "nested_depth");

  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = yr_fetch_block_data(block);

    if (block_data == NULL)
      continue;

    ZIP_ARCHIVE archive;
    int parse_result = zip_parse(block_data, block->size, &archive);

    if (parse_result != 1)
      continue;

    ZIP_NESTED_CONTEXT nested_context = {ZIP_NESTED_SCAN_BUDGET};
    uint64_t nested_depth = 0;

    if (!zip_measure_nested_depth(
            block_data,
            block->size,
            &archive,
            0,
            &nested_context,
            &nested_depth))
    {
      zip_free_archive(&archive);
      return ERROR_INSUFFICIENT_MEMORY;
    }

    ZIP_MODULE_DATA* zip = (ZIP_MODULE_DATA*) yr_malloc(sizeof(ZIP_MODULE_DATA));

    if (zip == NULL)
    {
      zip_free_archive(&archive);
      return ERROR_INSUFFICIENT_MEMORY;
    }

    zip->entries = archive.entries;
    zip->entries_count = archive.entries_count;
    module_object->data = zip;

    yr_set_integer(1, module_object, "valid");
    yr_set_integer((int64_t) archive.entries_count, module_object, "entries");
    yr_set_integer(
        (int64_t) archive.uncompressed_size,
        module_object,
        "uncompressed_size");
    yr_set_integer(
        (int64_t) archive.compressed_size,
        module_object,
        "compressed_size");
    yr_set_float(archive.max_ratio, module_object, "max_ratio");
    yr_set_integer(archive.is_encrypted, module_object, "is_encrypted");
    yr_set_integer(archive.has_traversal, module_object, "has_traversal");
    yr_set_integer((int64_t) nested_depth, module_object, "nested_depth");

    archive.entries = NULL;
    archive.entries_count = 0;
    zip_free_archive(&archive);
    break;
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  ZIP_MODULE_DATA* zip = (ZIP_MODULE_DATA*) module_object->data;

  if (zip == NULL)
    return ERROR_SUCCESS;

  for (size_t i = 0; i < zip->entries_count; i++)
    yr_free(zip->entries[i].name);

  yr_free(zip->entries);
  yr_free(zip);

  return ERROR_SUCCESS;
}

#undef MODULE_NAME
