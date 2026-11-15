
.. _dotnet-module:

#############
dotnet module
#############

.. versionadded:: 3.6.0

The dotnet module allows you to create more fine-grained rules for .NET files by
using attributes and features of the .NET file format. Let's see some examples:

.. code-block:: yara

    import "dotnet"

    rule not_exactly_five_streams
    {
        condition:
            dotnet.number_of_streams != 5
    }

    rule blop_stream
    {
        condition:
            for any i in (0..dotnet.number_of_streams - 1):
                (dotnet.streams[i].name == "#Blop")
    }

Reference
---------

.. c:type:: version

    The version string contained in the metadata root.

    *Example: dotnet.version == "v2.0.50727"*

.. c:type:: module_name

    The name of the module.

    *Example: dotnet.module_name == "axs"*

.. c:type:: number_of_streams

    The number of streams in the file.

.. c:type:: streams

    A zero-based array of stream objects, one for each stream contained in the
    file. Individual streams can be accessed by using the [] operator. Each
    stream object has the following attributes:

    .. c:member:: name

        Stream name.

    .. c:member:: offset

        Stream offset.

    .. c:member:: size

        Stream size.

    *Example: dotnet.streams[0].name == "#~"*

.. c:type:: number_of_guids

    The number of GUIDs in the guids array.

.. c:type:: guids

    A zero-based array of strings, one for each GUID. Individual guids can be
    accessed by using the [] operator.

    *Example: dotnet.guids[0] == "99c08ffd-f378-a891-10ab-c02fe11be6ef"*

.. c:type:: number_of_classes
    The number of classes in the file.

.. c:type:: classes
    An array of .NET classes stored in the metadata. Individual classes can be accessed
    using the [] operator. Each class object contains the following attributes:

    .. c:member:: fullname
        Class full name.

    .. c:member:: name
        Class name.

    .. c:member:: namespace
        Class namespace.

    .. c:member:: visibility
        Class visibility specifier, options are:

        ``private``
        ``public``
        ``protected``
        ``internal``
        ``private protected``
        ``protected internal``

    .. c:member:: type
        Type of the object, options are:

        ``class``
        ``interface``

    .. c:member:: abstract
        Boolean representing if class is abstract.

    .. c:member:: sealed
        Boolean representing if class is sealed.

    .. c:member:: number_of_generic_parameters
        Number of generic parameters.

    .. c:member:: generic_parameters
        A zero-based array of generic parameters name. Individual parameters can be accessed using the [] operator.

    .. c:member:: number_of_base_types
        Number of the base types.

    .. c:member:: base_types
        A zero-based array of base types name. Individual base types can be accessed using the [] operator.

    .. c:member:: number_of_methods
        Number of the methods.

    .. c:member:: methods
        A zero-based array of method objects. Individual methods can be accessed by
        using the [] operator. Each object contains following attributes:

        .. c:member:: name
            Method name.

        .. c:member:: visibility
            Method visibility specifier, options are:

            ``private``
            ``public``
            ``protected``
            ``internal``
            ``private protected``
            ``protected internal``

        .. c:member:: static
            Boolean representing if method is static.

        .. c:member:: virtual
            Boolean representing if method is virtual. 

        .. c:member:: final
            Boolean representing if method is final. 

        .. c:member:: abstract
            Boolean representing if method is abstract. 

        .. c:member:: return_type
            Method return type name.

        .. c:member:: number_of_parameters
            Number of the method parameters.

        .. c:member:: parameters
            A zero-based array of method parameters. Individual parameters can be accessed by using the [] operator.

            .. c:member:: name
                Parameter name.

            .. c:member:: type
                Parameter type.

        .. c:member:: number_of_generic_parameters
            Number of the method generic parameters.

        .. c:member:: generic_parameters
            A zero-based array of method generic parameters. Individual parameters can be accessed by using the [] operator.

        .. c:member:: has_body
            Boolean indicating whether the method has a readable Common
            Intermediate Language (CIL) method body.

        .. c:member:: is_tiny
            Boolean indicating whether the method body uses the tiny header
            format.

        .. c:member:: is_fat
            Boolean indicating whether the method body uses the fat header
            format.

        .. c:member:: format
            Method body format: ``tiny``, ``fat``, or ``none``.

        .. c:member:: rva
            Relative virtual address of the method body.

        .. c:member:: offset
            File offset of the method body.

        .. c:member:: header_size
            Size in bytes of the method body header.

        .. c:member:: code_offset
            File offset of the first IL instruction.

        .. c:member:: code_size
            Size in bytes of the IL instruction stream.

        .. c:member:: body_size
            Total size of the method body, including the header, IL stream,
            and exception sections.

        .. c:member:: max_stack
            Maximum evaluation stack depth declared by the method body.

        .. c:member:: local_var_sig_tok
            Metadata token of the local variable signature, or zero when the
            method has no local variables.

        .. c:member:: flags
            Raw method body header flags.

        .. c:member:: init_locals
            Boolean indicating whether local variables must be initialized.

        .. c:member:: number_of_instructions
            Number of decoded IL instructions.

        .. c:member:: instructions
            A zero-based array of IL instruction objects. Individual
            instructions can be accessed using the [] operator.

            .. c:member:: offset
                IL offset relative to the start of the instruction stream.

            .. c:member:: file_offset
                File offset of the instruction.

            .. c:member:: rva
                Relative virtual address of the instruction.

            .. c:member:: opcode
                Numeric opcode. One-byte opcodes use their ECMA-335 value;
                two-byte opcodes include the ``0xFE`` prefix, for example
                ``0xFE01`` for ``ceq``.

            .. c:member:: opcode_size
                Size of the opcode in bytes (1 or 2).

            .. c:member:: opcode_name
                Instruction mnemonic, for example ``callvirt``.

            .. c:member:: mnemonic
                Alias for ``opcode_name``.

            .. c:member:: operand
                Decoded operand. Metadata tokens, variable indexes, branch
                displacements, and integer constants are represented as
                integers. For ``switch`` this is the number of targets.

            .. c:member:: operand_size
                Size of the operand in bytes.

            .. c:member:: size
                Total instruction size in bytes, including the opcode and
                operand.

            .. c:member:: branch_target
                For branch instructions, the target IL offset. This member is
                only defined for branch opcodes.

            .. c:member:: number_of_switch_targets
                For ``switch`` instructions, the number of branch targets.

            .. c:member:: switch_targets
                For ``switch`` instructions, a zero-based array of target IL
                offsets.

        .. c:member:: number_of_opcodes
            Number of opcodes in the method body. This is the same as
            ``number_of_instructions``.

        .. c:member:: opcodes
            A zero-based integer array containing only the numeric opcodes of
            the method, without operands.

        .. c:member:: number_of_exception_handlers
            Number of exception handlers in the method body.

        .. c:member:: exception_handlers
            A zero-based array of exception handler objects. Individual
            handlers can be accessed using the [] operator.

            .. c:member:: type
                Handler type: ``catch``, ``filter``, ``finally``, ``fault``,
                or ``unknown``.

            .. c:member:: flags
                Raw exception clause flags.

            .. c:member:: try_offset
                IL offset where the protected region starts.

            .. c:member:: try_length
                Length in bytes of the protected region.

            .. c:member:: try_end
                IL offset immediately after the protected region.

            .. c:member:: handler_offset
                IL offset where the handler starts.

            .. c:member:: handler_length
                Length in bytes of the handler.

            .. c:member:: handler_end
                IL offset immediately after the handler.

            .. c:member:: class_token
                Metadata token of the caught type for ``catch`` clauses, or
                zero for other handler types.

            .. c:member:: filter_offset
                IL offset of the filter expression for ``filter`` clauses, or
                zero for other handler types.

        .. c:member:: number_of_exception_regions
            Alias for ``number_of_exception_handlers``.

        .. c:member:: exception_regions
            Alias for ``exception_handlers``.

    *Example: dotnet.classes[0].fullname == "Launcher.Program"*

    *Example: dotnet.classes[0].methods[0].instructions[0].opcode == 0x28*

.. c:type:: number_of_resources

    The number of resources in the .NET file. These are different from normal PE
    resources.

.. c:type:: resources

    A zero-based array of resource objects, one for each resource the .NET file
    has.  Individual resources can be accessed by using the [] operator. Each
    resource object has the following attributes:

    .. c:member:: offset

        Offset for the resource data.

    .. c:member:: length

        Length of the resource data.

    .. c:member:: name

        Name of the resource (string).

    *Example: uint16be(dotnet.resources[0].offset) == 0x4d5a*

.. c:type:: assembly

    Object for .NET assembly information.

    .. c:member:: version

        An object with integer values representing version information for this
        assembly. Attributes are:

        ``major``
        ``minor``
        ``build_number``
        ``revision_number``

    .. c:member:: name

        String containing the assembly name.

    .. c:member:: culture

        String containing the culture (language/country/region) for this
        assembly.

    *Example: dotnet.assembly.name == "Keylogger"*

    *Example: dotnet.assembly.version.major == 7 and dotnet.assembly.version.minor == 0*

.. c:type:: number_of_modulerefs

    The number of module references in the .NET file.

.. c:type:: modulerefs

    A zero-based array of strings, one for each module reference the .NET file
    has.  Individual module references can be accessed by using the []
    operator.

    *Example: dotnet.modulerefs[0] == "kernel32"*

.. c:type:: typelib

    The typelib of the file.

.. c:type:: number_of_constants

    The number of constants in the .NET file.

.. c:type:: constants

    A zero-based array of strings, one for each constant the .NET file has. 
    Individual constants can be accessed by using the [] operator.

.. c:type:: number_of_assembly_refs

    The number of objects for .NET assembly reference information.

.. c:type:: assembly_refs

    Object for .NET assembly reference information.

    .. c:member:: version

        An object with integer values representing version information for this
        assembly. Attributes are:

        ``major``
        ``minor``
        ``build_number``
        ``revision_number``

    .. c:member:: name

        String containing the assembly name.

    .. c:member:: public_key_or_token

        String containing the public key or token which identifies the author of
        this assembly.

.. c:type:: number_of_user_strings

    The number of user strings in the file.

.. c:type:: user_strings

    An zero-based array of user strings, one for each stream contained in the
    file. Individual strings can be accessed by using the [] operator.

.. c:type:: number_of_field_offsets

    The number of fields in the field_offsets array.

.. c:type:: field_offsets

    A zero-based array of integers, one for each field. Individual field offsets
    can be accessed by using the [] operator.

    *Example: dotnet.field_offsets[0] == 8675309*

.. c:type:: is_dotnet

    .. versionadded:: 4.2.0

    Function returning true if the PE is indeed .NET.

    *Example: dotnet.is_dotnet*

Functions
---------

.. c:function:: opcode_sequence(pattern)

    .. versionadded:: 4.6.0

    Returns true if any decoded method contains the opcode sequence described
    by ``pattern``. Operands are ignored, so the sequence only describes
    consecutive instruction opcodes.

    ``pattern`` is a whitespace- or comma-separated list of opcodes. Each item
    can be a mnemonic (``callvirt``), a decimal value (``111``), or a
    hexadecimal value (``0x6F`` or ``0xFE01``). Two wildcards are supported:
    ``?`` or ``??`` match any single opcode, and ``*`` or ``...`` match any
    number of opcodes, including zero.

    *Example: dotnet.opcode_sequence("ldarg.0, stsfld, ldarg.1, stsfld")*

    *Example: dotnet.opcode_sequence("call, *, callvirt")*

.. c:function:: opcode_sequence(method, pattern)

    Like ``opcode_sequence(pattern)``, but only considers methods matching
    ``method``. The selector can be a bare method name (``Initialize``),
    ``Class::Method``, or ``Namespace.Class.Method``.

    *Example: dotnet.opcode_sequence("Program::Main", "ldstr, call")*

.. c:function:: opcode_sequence(class_index, method_index, pattern)

    Like ``opcode_sequence(pattern)``, but only considers the method at the
    specified indexes in the ``classes`` and ``methods`` arrays.

    *Example: dotnet.opcode_sequence(0, 0, "ldarg.0, call")*

.. c:function:: opcode_sequence(opcode1, opcode2, ...)

    Matches an exact sequence of numeric opcodes in any method. Up to eight
    opcodes can be supplied.

    *Example: dotnet.opcode_sequence(0x28, 0x2A)*

``il_opcode_sequence`` is an alias for ``opcode_sequence``.
