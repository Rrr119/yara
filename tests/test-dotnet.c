#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <yara.h>

#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  init_top_srcdir();

  yr_initialize();

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          not dotnet.is_dotnet \
      }",
      "tests/data/tiny");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.assembly.name == \"hpjsoaputility.Sv.resources\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.number_of_resources == 1 and \
          dotnet.resources[0].offset == 724 and \
          dotnet.resources[0].length == 180 and \
          dotnet.resources[0].name == \"hpjsoaputility.XmlStreamSoapExtension.pt.resources\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.number_of_guids == 1 and \
          dotnet.guids[0] == \"3764d539-e21a-4366-bc7c-b56fa67efbb0\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.number_of_streams == 5 and \
          dotnet.streams[0].name == \"#~\" and \
          dotnet.streams[1].name == \"#Strings\" and \
          dotnet.streams[2].name == \"#US\" and \
          dotnet.streams[3].name == \"#GUID\" and \
          dotnet.streams[4].name == \"#Blob\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.module_name == \"hpjsoaputility.Sv.resources.dll\" and \
          dotnet.version == \"v2.0.50727\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.classes[0].fullname == \"Autodesk.AutoCAD.Internal.Windows.MenuServices\" and \
          dotnet.classes[0].name == \"MenuServices\" and \
          dotnet.classes[0].namespace == \"Autodesk.AutoCAD.Internal.Windows\" and \
          dotnet.classes[0].visibility == \"public\" and \
          dotnet.classes[0].type == \"class\" and \
          dotnet.classes[0].abstract and \
          dotnet.classes[0].sealed and \
          dotnet.classes[0].number_of_generic_parameters == 0 and \
          dotnet.classes[0].number_of_base_types == 1 and \
          dotnet.classes[0].base_types[0] == \"System.Object\" and \
          dotnet.classes[0].number_of_methods == 20 and \
          dotnet.classes[0].methods[0].name == \"Initialize\" and \
          dotnet.classes[0].methods[0].visibility == \"public\" and \
          dotnet.classes[0].methods[0].static and \
          not dotnet.classes[0].methods[0].virtual and \
          not dotnet.classes[0].methods[0].final and \
          dotnet.classes[0].methods[0].return_type == \"void\" and \
          dotnet.classes[0].methods[0].parameters[0].name == \"productName\" and \
          dotnet.classes[0].methods[0].parameters[0].type == \"string\" and \
          dotnet.classes[0].methods[0].parameters[1].name == \"maxRecentFiles\" and \
          dotnet.classes[0].methods[0].parameters[1].type == \"int\" and \
          dotnet.classes[0].methods[0].number_of_generic_parameters == 0 and \
          dotnet.classes[156].fullname == \"Autodesk.AutoCAD.Ribbon.Point3dDoubleToStringConverter\" and \
          dotnet.classes[156].name == \"Point3dDoubleToStringConverter\" and \
          dotnet.classes[156].namespace == \"Autodesk.AutoCAD.Ribbon\" and \
          dotnet.classes[156].number_of_base_types == 2 and \
          dotnet.classes[156].base_types[0] == \"System.Object\" and \
          dotnet.classes[156].base_types[1] == \"System.Windows.Data.IValueConverter\" and \
          dotnet.classes[156].number_of_methods == 3 and \
          dotnet.classes[156].methods[0].name == \"Convert\" and \
          dotnet.classes[156].methods[0].return_type == \"object\" and \
          dotnet.classes[156].methods[0].number_of_parameters == 4 and \
          dotnet.classes[156].methods[0].parameters[0].name == \"value\" and \
          dotnet.classes[156].methods[0].parameters[0].type == \"object\" and \
          dotnet.classes[156].methods[0].parameters[1].name == \"targetType\" and \
          dotnet.classes[156].methods[0].parameters[1].type == \"System.Type\" and \
          dotnet.classes[156].methods[0].parameters[2].name == \"parameter\" and \
          dotnet.classes[156].methods[0].parameters[2].type == \"object\" and \
          dotnet.classes[156].methods[0].parameters[3].name == \"culture\" and \
          dotnet.classes[156].methods[0].parameters[3].type == \"System.Globalization.CultureInfo\" \
      }",
      "tests/data/"
      "756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59");

  assert_false_rule(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.version == \"v4.0.30319\" \
      }",
      "tests/data/"
      "bad_dotnet_pe");

  // #GUID stream offset is not 4-byte aligned, the guid is read through the
  // unaligned helpers so this must parse cleanly (traps under -fsanitize=
  // alignment otherwise).
  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet \
      }",
      "tests/data/dotnet_misaligned_guid");

  // Fat method body: Initialize, the first method of the first class.
  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.classes[0].methods[0].name == \"Initialize\" and \
          dotnet.classes[0].methods[0].has_body and \
          dotnet.classes[0].methods[0].is_fat and \
          not dotnet.classes[0].methods[0].is_tiny and \
          dotnet.classes[0].methods[0].format == \"fat\" and \
          dotnet.classes[0].methods[0].rva == 0x14dabc and \
          dotnet.classes[0].methods[0].header_size == 12 and \
          dotnet.classes[0].methods[0].code_size == 267 and \
          dotnet.classes[0].methods[0].max_stack == 4 and \
          dotnet.classes[0].methods[0].flags == 0x003 and \
          not dotnet.classes[0].methods[0].init_locals and \
          dotnet.classes[0].methods[0].number_of_instructions == 64 and \
          dotnet.classes[0].methods[0].number_of_opcodes == 64 and \
          dotnet.classes[0].methods[0].instructions[0].opcode == 0x02 and \
          dotnet.classes[0].methods[0].instructions[0].mnemonic == \"ldarg.0\" and \
          dotnet.classes[0].methods[0].instructions[1].opcode == 0x80 and \
          dotnet.classes[0].methods[0].instructions[1].operand == 0x04000007 and \
          dotnet.classes[0].methods[0].instructions[6].opcode == 0x28 and \
          dotnet.classes[0].methods[0].instructions[6].mnemonic == \"call\" and \
          dotnet.classes[0].methods[0].instructions[6].operand == 0x0A00000F and \
          dotnet.classes[0].methods[0].instructions[9].opcode == 0xFE01 and \
          dotnet.classes[0].methods[0].instructions[9].opcode_name == \"ceq\" and \
          dotnet.classes[0].methods[0].instructions[9].size == 2 and \
          dotnet.classes[0].methods[0].opcodes[0] == 0x02 and \
          dotnet.classes[0].methods[0].opcodes[9] == 0xFE01 \
      }",
      "tests/data/"
      "756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59");

  // Tiny method body: Application_BeginQuit, method 1 of the first class.
  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.classes[0].methods[1].name == \"Application_BeginQuit\" and \
          dotnet.classes[0].methods[1].has_body and \
          dotnet.classes[0].methods[1].is_tiny and \
          not dotnet.classes[0].methods[1].is_fat and \
          dotnet.classes[0].methods[1].format == \"tiny\" and \
          dotnet.classes[0].methods[1].header_size == 1 and \
          dotnet.classes[0].methods[1].code_size == 6 and \
          dotnet.classes[0].methods[1].max_stack == 8 and \
          dotnet.classes[0].methods[1].body_size == 7 and \
          dotnet.classes[0].methods[1].number_of_instructions == 2 and \
          dotnet.classes[0].methods[1].instructions[0].opcode == 0x28 and \
          dotnet.classes[0].methods[1].instructions[0].operand == 0x06000013 and \
          dotnet.classes[0].methods[1].instructions[1].opcode == 0x2A and \
          dotnet.classes[0].methods[1].instructions[1].mnemonic == \"ret\" \
      }",
      "tests/data/"
      "756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59");

  // LoadMenuMacros has two finally clauses in a small exception section.
  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.classes[0].methods[7].name == \"LoadMenuMacros\" and \
          dotnet.classes[0].methods[7].init_locals and \
          dotnet.classes[0].methods[7].number_of_instructions == 57 and \
          dotnet.classes[0].methods[7].number_of_exception_handlers == 2 and \
          dotnet.classes[0].methods[7].number_of_exception_regions == 2 and \
          dotnet.classes[0].methods[7].exception_handlers[0].type == \"finally\" and \
          dotnet.classes[0].methods[7].exception_handlers[0].flags == 2 and \
          dotnet.classes[0].methods[7].exception_handlers[0].try_offset == 73 and \
          dotnet.classes[0].methods[7].exception_handlers[0].try_length == 46 and \
          dotnet.classes[0].methods[7].exception_handlers[0].try_end == 119 and \
          dotnet.classes[0].methods[7].exception_handlers[0].handler_offset == 119 and \
          dotnet.classes[0].methods[7].exception_handlers[0].handler_length == 14 and \
          dotnet.classes[0].methods[7].exception_handlers[0].handler_end == 133 and \
          dotnet.classes[0].methods[7].exception_regions[1].try_offset == 25 and \
          dotnet.classes[0].methods[7].exception_regions[1].try_length == 119 and \
          dotnet.classes[0].methods[7].exception_regions[1].handler_offset == 144 \
      }",
      "tests/data/"
      "756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59");

  // FillOpenDocuments uses a fat exception section with a catch clause.
  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.classes[0].methods[9].name == \"FillOpenDocuments\" and \
          dotnet.classes[0].methods[9].number_of_exception_handlers == 3 and \
          dotnet.classes[0].methods[9].exception_handlers[0].type == \"finally\" and \
          dotnet.classes[0].methods[9].exception_handlers[0].try_offset == 83 and \
          dotnet.classes[0].methods[9].exception_handlers[0].try_length == 23 and \
          dotnet.classes[0].methods[9].exception_handlers[0].handler_offset == 106 and \
          dotnet.classes[0].methods[9].exception_handlers[1].type == \"catch\" and \
          dotnet.classes[0].methods[9].exception_handlers[1].class_token == 0x01000001 and \
          dotnet.classes[0].methods[9].exception_handlers[1].try_offset == 116 and \
          dotnet.classes[0].methods[9].exception_handlers[1].try_length == 141 and \
          dotnet.classes[0].methods[9].exception_handlers[1].handler_offset == 257 and \
          dotnet.classes[0].methods[9].exception_handlers[1].handler_length == 3 and \
          dotnet.classes[0].methods[9].exception_handlers[2].type == \"finally\" and \
          dotnet.classes[0].methods[9].exception_handlers[2].try_offset == 18 and \
          dotnet.classes[0].methods[9].exception_handlers[2].try_length == 263 \
      }",
      "tests/data/"
      "756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.opcode_sequence(\"ldarg.0, stsfld, ldarg.1, stsfld\") and \
          dotnet.opcode_sequence(\"Initialize\", \"ldarg.0, stsfld, ldarg.1, stsfld\") and \
          dotnet.opcode_sequence(0, 0, \"ldarg.0, stsfld\") and \
          dotnet.opcode_sequence(0x28, 0x2A) and \
          dotnet.opcode_sequence(\"Initialize\", \"ldarg.0, *, ceq\") and \
          dotnet.il_opcode_sequence(\"0x28, 0x2A\") and \
          not dotnet.opcode_sequence(\"Initialize\", \"ret, ret\") and \
          not dotnet.opcode_sequence(\"NoSuchMethod\", \"*\") \
      }",
      "tests/data/"
      "756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59");

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
