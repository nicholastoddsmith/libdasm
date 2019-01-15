
/*
 * pydasm -- Python module wrapping libdasm
 * Copyright (c) 2005       Ero Carrera Ventura <ero / dkbza.org> (Python adaptation)
 * Copyright (c) 2004-2007  Jarkko Turkulainen <jt / nologin.org> <turkja / github.com>
 * Copyright (c) 2009-2010  Ange Albertini <angea / github.com>
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1) Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <Python.h>
#include "structmember.h"
#include "../libdasm.h"


#define INSTRUCTION_STR_BUFFER_LENGTH   256

/*
    Instruction types borrowed from
    "libdasm.h"
*/
char* instruction_types[] = {
	"INSTRUCTION_TYPE_ASC",
	"INSTRUCTION_TYPE_DCL",
	"INSTRUCTION_TYPE_MOV",
	"INSTRUCTION_TYPE_MOVSR",
	"INSTRUCTION_TYPE_ADD",
	"INSTRUCTION_TYPE_XADD",
	"INSTRUCTION_TYPE_ADC",
	"INSTRUCTION_TYPE_SUB",
	"INSTRUCTION_TYPE_SBB",
	"INSTRUCTION_TYPE_INC",
	"INSTRUCTION_TYPE_DEC",
	"INSTRUCTION_TYPE_DIV",
	"INSTRUCTION_TYPE_IDIV",
	"INSTRUCTION_TYPE_NOT",
	"INSTRUCTION_TYPE_NEG",
	"INSTRUCTION_TYPE_STOS",
	"INSTRUCTION_TYPE_LODS",
	"INSTRUCTION_TYPE_SCAS",
	"INSTRUCTION_TYPE_MOVS",
	"INSTRUCTION_TYPE_MOVSX",
	"INSTRUCTION_TYPE_MOVZX",
	"INSTRUCTION_TYPE_CMPS",
	"INSTRUCTION_TYPE_SHX",
	"INSTRUCTION_TYPE_ROX",
	"INSTRUCTION_TYPE_MUL",
	"INSTRUCTION_TYPE_IMUL",
	"INSTRUCTION_TYPE_EIMUL",
	"INSTRUCTION_TYPE_XOR",
	"INSTRUCTION_TYPE_LEA",
	"INSTRUCTION_TYPE_XCHG",
	"INSTRUCTION_TYPE_CMP",
	"INSTRUCTION_TYPE_TEST",
	"INSTRUCTION_TYPE_PUSH",
	"INSTRUCTION_TYPE_AND",
	"INSTRUCTION_TYPE_OR",
	"INSTRUCTION_TYPE_POP",
	"INSTRUCTION_TYPE_JMP",
	"INSTRUCTION_TYPE_JMPC",
	"INSTRUCTION_TYPE_JECXZ",
	"INSTRUCTION_TYPE_SETC",
	"INSTRUCTION_TYPE_MOVC",
	"INSTRUCTION_TYPE_LOOP",
	"INSTRUCTION_TYPE_CALL",
	"INSTRUCTION_TYPE_RET",
	"INSTRUCTION_TYPE_ENTER",
	"INSTRUCTION_TYPE_INT",
	"INSTRUCTION_TYPE_BT",
	"INSTRUCTION_TYPE_BTS",
	"INSTRUCTION_TYPE_BTR",
	"INSTRUCTION_TYPE_BTC",
	"INSTRUCTION_TYPE_BSF",
	"INSTRUCTION_TYPE_BSR",
	"INSTRUCTION_TYPE_BSWAP",
	"INSTRUCTION_TYPE_SGDT",
	"INSTRUCTION_TYPE_SIDT",
	"INSTRUCTION_TYPE_SLDT",
	"INSTRUCTION_TYPE_LFP",
	"INSTRUCTION_TYPE_CLD",
	"INSTRUCTION_TYPE_STD",
	"INSTRUCTION_TYPE_XLAT",
	"INSTRUCTION_TYPE_FCMOVC",
	"INSTRUCTION_TYPE_FADD",
	"INSTRUCTION_TYPE_FADDP",
	"INSTRUCTION_TYPE_FIADD",
	"INSTRUCTION_TYPE_FSUB",
	"INSTRUCTION_TYPE_FSUBP",
	"INSTRUCTION_TYPE_FISUB",
	"INSTRUCTION_TYPE_FSUBR",
	"INSTRUCTION_TYPE_FSUBRP",
	"INSTRUCTION_TYPE_FISUBR",
	"INSTRUCTION_TYPE_FMUL",
	"INSTRUCTION_TYPE_FMULP",
	"INSTRUCTION_TYPE_FIMUL",
	"INSTRUCTION_TYPE_FDIV",
	"INSTRUCTION_TYPE_FDIVP",
	"INSTRUCTION_TYPE_FDIVR",
	"INSTRUCTION_TYPE_FDIVRP",
	"INSTRUCTION_TYPE_FIDIV",
	"INSTRUCTION_TYPE_FIDIVR",
	"INSTRUCTION_TYPE_FCOM",
	"INSTRUCTION_TYPE_FCOMP",
	"INSTRUCTION_TYPE_FCOMPP",
	"INSTRUCTION_TYPE_FCOMI",
	"INSTRUCTION_TYPE_FCOMIP",
	"INSTRUCTION_TYPE_FUCOM",
	"INSTRUCTION_TYPE_FUCOMP",
	"INSTRUCTION_TYPE_FUCOMPP",
	"INSTRUCTION_TYPE_FUCOMI",
	"INSTRUCTION_TYPE_FUCOMIP",
	"INSTRUCTION_TYPE_FST",
	"INSTRUCTION_TYPE_FSTP",
	"INSTRUCTION_TYPE_FIST",
	"INSTRUCTION_TYPE_FISTP",
	"INSTRUCTION_TYPE_FISTTP",
	"INSTRUCTION_TYPE_FLD",
	"INSTRUCTION_TYPE_FILD",
	"INSTRUCTION_TYPE_FICOM",
	"INSTRUCTION_TYPE_FICOMP",
	"INSTRUCTION_TYPE_FFREE",
	"INSTRUCTION_TYPE_FFREEP",
	"INSTRUCTION_TYPE_FXCH",
	"INSTRUCTION_TYPE_SYSENTER",
	"INSTRUCTION_TYPE_FPU_CTRL",
	"INSTRUCTION_TYPE_FPU",
	"INSTRUCTION_TYPE_MMX",
	"INSTRUCTION_TYPE_SSE",
	"INSTRUCTION_TYPE_OTHER",
	"INSTRUCTION_TYPE_PRIV",
    NULL };

/*
    Operand types borrowed from
    "libdasm.h"
*/
char* operand_types[] = {
	"OPERAND_TYPE_NONE",
	"OPERAND_TYPE_MEMORY",
	"OPERAND_TYPE_REGISTER",
	"OPERAND_TYPE_IMMEDIATE",
    NULL };

/*
    Registers borrowed from
    "libdasm.h"
*/
char* registers[] = {
    "REGISTER_EAX",
    "REGISTER_ECX",
    "REGISTER_EDX",
    "REGISTER_EBX",
    "REGISTER_ESP",
    "REGISTER_EBP",
    "REGISTER_ESI",
    "REGISTER_EDI",
    "REGISTER_NOP",
    NULL };


/*
    Register types borrowed from
    "libdasm.h"
*/
char* register_types[] = {
    "REGISTER_TYPE_GEN",
    "REGISTER_TYPE_SEGMENT",
    "REGISTER_TYPE_DEBUG",
    "REGISTER_TYPE_CONTROL",
    "REGISTER_TYPE_TEST",
    "REGISTER_TYPE_XMM",
    "REGISTER_TYPE_MMX",
    "REGISTER_TYPE_FPU",
    NULL };

//===========================================================
//Structure definitions
//===========================================================
	
typedef struct {
    PyObject_HEAD
} PyDAsmObject;

typedef struct {
    PyObject_HEAD
    PyObject*  mnemonic; 
    int flags1;
	int flags2;
	int flags3;
	int modrm;
	int type;
} PyInstObject;

typedef struct {
    PyObject_HEAD
    int length;
	int type;
	int mode;
	int opcode;
	int modrm;
	int sib;
	int extindex;
	int fpuindex;
	int dispbytes;
	int immbytes;
	int sectionbytes;
	PyObject* op1;
	PyObject* op2;
	PyObject* op3;
	PyObject* ptr;
	int flags;
	int eflags_affected;
	int eflags_used;
} PyInstructionObject;

typedef struct {
	PyObject_HEAD
	int type;
	int reg;
	int basereg;
	int indexreg;
	int scale;
	int dispbytes;
	int dispoffset;
	int immbytes;
	int immoffset;
	int sectionbytes;
	int section;
	int displacement;
	int immediate;
	int flags;
} PyOperandObject;

//===========================================================
//Forward definitions
//===========================================================

PyObject* CreateInstObj(INST *pinst);
PyObject* CreateOperandObj(OPERAND *op);
PyObject* CreateInstructionObj(INSTRUCTION *insn);

//===========================================================
//Dealloc routines
//===========================================================

static void DAsm_dealloc(PyDAsmObject* self) {
	Py_TYPE(self)->tp_free((PyObject*) self);
}

static void Inst_dealloc(PyInstObject* self) {
	Py_XDECREF(self->mnemonic);
	Py_TYPE(self)->tp_free((PyObject*) self);
}

static void Instruction_dealloc(PyInstructionObject* self) {
	Py_XDECREF(self->op1);
	Py_XDECREF(self->op2);
	Py_XDECREF(self->op3);
	Py_XDECREF(self->ptr);
	Py_TYPE(self)->tp_free((PyObject*) self);
}

static void Operand_dealloc(PyOperandObject* self) {
	Py_TYPE(self)->tp_free((PyObject*) self);
}

//===========================================================
//New routines
//===========================================================
//Macro for assigning Py_None and incrementing its ref count
#define PY_NONE_INCREF Py_None; Py_INCREF(Py_None)

static PyObject* DAsm_new(PyTypeObject *type, PyObject* args, PyObject* kwds) {
	PyDAsmObject* self = (PyDAsmObject*) type->tp_alloc(type, 0);
	if(NULL == self)
		return NULL;
	return (PyObject*) self;
}

static PyObject* Instruction_new(PyTypeObject *type, PyObject* args, PyObject* kwds) {
	PyInstructionObject* self = (PyInstructionObject*) type->tp_alloc(type, 0);
	if(NULL == self)
		return NULL;
	
	self->length = 0;
	self->type = 0;
	self->mode = 0;
	self->opcode = 0;
	self->modrm = 0;
	self->sib = 0;
	self->extindex = 0;
	self->fpuindex = 0;
	self->dispbytes = 0;
	self->immbytes = 0;
	self->sectionbytes = 0;
	
	self->op1 = PY_NONE_INCREF;
	self->op2 = PY_NONE_INCREF;
	self->op3 = PY_NONE_INCREF;
	self->ptr = PY_NONE_INCREF;
	
	self->flags = 0;
	self->eflags_affected = 0;
	self->eflags_used = 0;
	
	return (PyObject*) self;
}

static PyObject* Inst_new(PyTypeObject *type, PyObject* args, PyObject* kwds) {
	PyInstObject* self = (PyInstObject*) type->tp_alloc(type, 0);
	if(NULL == self)
		return NULL;
	self->mnemonic = PyUnicode_FromString("");
    if(NULL == self->mnemonic) {
		Py_DECREF(self);
        return NULL;
    }
	self->flags1 = 0;
	self->flags2 = 0;
	self->flags3 = 0;
	self->modrm = 0;
	self->type = 0;
	
	return (PyObject*) self;
}

static PyObject* Operand_new(PyTypeObject *type, PyObject* args, PyObject* kwds) {
	PyOperandObject* self = (PyOperandObject*) type->tp_alloc(type, 0);
	if(NULL == self)
		return NULL;
	self->type = 0;
	self->reg = 0;
	self->basereg = 0;
	self->indexreg = 0;
	self->scale = 0;
	self->dispbytes = 0;
	self->dispoffset = 0;
	self->immbytes = 0;
	self->immoffset;
	self->sectionbytes = 0;
	self->section = 0;
	self->displacement = 0;
	self->immediate = 0;
	self->flags = 0;
	return (PyObject*) self;
}

//===========================================================
//init routines
//===========================================================

static int DAsm_init(PyDAsmObject* self, PyObject* args, PyObject* kwds) {
	return 0;
}

static int Inst_init(PyInstObject* self, PyObject* args, PyObject* kwds) {
	return 0;
}

static int Instruction_init(PyInstructionObject* self, PyObject* args, PyObject* kwds) {
	return 0;
}

static int Operand_init(PyOperandObject* self, PyObject* args, PyObject* kwds) {
	return 0;
}

//===========================================================
//Definitions of attributes
//===========================================================

static PyMemberDef DAsmMembers[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef InstMembers[] = {
    {"mnemonic", T_OBJECT_EX, offsetof(PyInstObject, mnemonic), 0, "instruction mnemonic"},
    {"flags1", 	 T_INT, offsetof(PyInstObject, flags1), 		0, "flag one"},
    {"flags2", 	 T_INT, offsetof(PyInstObject, flags2), 		0, "flag two"},
	{"flags3", 	 T_INT, offsetof(PyInstObject, flags3), 		0, "flag three"},
	{"modrm", 	 T_INT, offsetof(PyInstObject, modrm),  		0, "modrm"},
	{"type", 	 T_INT, offsetof(PyInstObject, type), 			0, "instruction type"},
    {NULL}  /* Sentinel */
};

static PyMemberDef InstructionMembers[] = {
	{"length", 		 	T_INT, 		 offsetof(PyInstructionObject, length), 		 0, "instruction length"},
	{"type", 		 	T_INT, 		 offsetof(PyInstructionObject, type), 			 0, "instruction type"},
	{"mode", 		 	T_INT, 		 offsetof(PyInstructionObject, mode), 			 0, "instruction mode"},
	{"opcode", 		 	T_INT, 		 offsetof(PyInstructionObject, opcode), 		 0, "instruction opcode"},
	{"modrm", 		 	T_INT, 		 offsetof(PyInstructionObject, modrm), 			 0, "instruction modrm"},
	{"sib", 	     	T_INT, 		 offsetof(PyInstructionObject, sib), 			 0, "instruction sib"},
	{"extindex", 	 	T_INT, 		 offsetof(PyInstructionObject, extindex), 		 0, "instruction extindex"},
	{"fpuindex", 	 	T_INT, 		 offsetof(PyInstructionObject, fpuindex), 		 0, "instruction fpuindex"},
	{"dispbytes", 	 	T_INT, 		 offsetof(PyInstructionObject, dispbytes), 		 0, "instruction dispbytes"},
	{"immbytes", 	 	T_INT, 		 offsetof(PyInstructionObject, immbytes), 		 0, "instruction immbytes"},
	{"sectionbytes", 	T_INT, 		 offsetof(PyInstructionObject, sectionbytes), 	 0, "instruction sectionbytes"},
	{"op1", 		 	T_OBJECT_EX, offsetof(PyInstructionObject, op1), 			 0, "instruction op1"},
	{"op2", 		 	T_OBJECT_EX, offsetof(PyInstructionObject, op2), 			 0, "instruction op2"},
	{"op3", 	     	T_OBJECT_EX, offsetof(PyInstructionObject, op3), 			 0, "instruction op3"},
	{"ptr", 		 	T_OBJECT_EX, offsetof(PyInstructionObject, ptr), 			 0, "instruction inst ptr"},
	{"flags", 		    T_INT, 	   	 offsetof(PyInstructionObject, flags), 			 0, "instruction flags"},
	{"eflags_affected", T_INT, 		 offsetof(PyInstructionObject, eflags_affected), 0, "instruction eflags_affected"},
	{"eflags_used", 	T_INT, 		 offsetof(PyInstructionObject, eflags_used), 	 0, "instruction eflags_used"},
    {NULL}  /* Sentinel */
};

static PyMemberDef OperandMembers[] = {
	{"type", 		 T_INT, offsetof(PyOperandObject, type), 		 0, "type"},
	{"reg", 	     T_INT, offsetof(PyOperandObject, reg), 		 0, "reg"},
	{"basereg", 	 T_INT, offsetof(PyOperandObject, basereg), 	 0, "base reg"},
	{"indexreg", 	 T_INT, offsetof(PyOperandObject, indexreg),     0, "index reg"},
    {"scale", 	 	 T_INT, offsetof(PyOperandObject, scale),	     0, "scale"},
	{"dispbytes", 	 T_INT, offsetof(PyOperandObject, dispbytes),    0, "disp bytes"},
	{"dispoffset", 	 T_INT, offsetof(PyOperandObject, dispoffset),   0, "disp offset"},
	{"immbytes", 	 T_INT, offsetof(PyOperandObject, immbytes), 	 0, "imm bytes"},
	{"immoffset", 	 T_INT, offsetof(PyOperandObject, immoffset), 	 0, "imm offset"},
	{"sectionbytes", T_INT, offsetof(PyOperandObject, sectionbytes), 0, "section bytes"},
	{"section", 	 T_INT, offsetof(PyOperandObject, section), 	 0, "section"},
	{"displacement", T_INT, offsetof(PyOperandObject, displacement), 0, "displacement"},
	{"immediate", 	 T_INT, offsetof(PyOperandObject, immediate),	 0, "immediate"},
	{"flags", 		 T_INT, offsetof(PyOperandObject, flags),	 	 0, "flags"},
    {NULL}  /* Sentinel */
};

/*
    Check whether we got a Python Object
*/
PyObject* CheckObj(PyObject* pObject)
{
	PyObject* pException;
	
	if(!pObject) {
		pException = PyErr_Occurred();
		if(pException)
            PyErr_Print();
        return NULL;
	}
    
    return pObject;
}

/*
    Assign an attribute "attr" named "name" to an object "obj"
*/
void AssignAttr(PyObject* obj, char* name, PyObject* attr)
{
    PyObject_SetAttrString(obj, name, attr);
    Py_DECREF(attr);
}

/*
    Get an attribute named "attr_name" from object "obj"
    The function steals the reference! note the decrement of
    the reference count.
*/
PyObject* GetAttr(PyObject* obj, char* attr_name)
{
    PyObject* pObj;
    
    pObj = PyObject_GetAttrString(obj, attr_name);
	if(!CheckObj(pObj)) {
        PyErr_SetString(PyExc_ValueError, "Can't get attribute from object");
        return NULL;
    }
    
    Py_DECREF(pObj);
    return pObj;
}

/*
    Get an Long attribute named "attr_name" from object "obj" and
    return it as a "long int"
*/
long int GetLongAttr(PyObject* o, char* attr_name)
{
    PyObject* pObj;
    
    pObj = GetAttr(o, attr_name);
	if(!pObj)
        return 0;
        
    return PyLong_AsLong(pObj);;
}

/*
    Fill an INST structure from the data in an "Inst" Python object.
*/
void FillInstStruct(PyObject* pPInst, PINST *_pinst)
{
    ssize_t mnemonic_length;
    PINST pinst;
    
    if(!pPInst || !_pinst)
        return;
        
    *_pinst = (PINST)calloc(1, sizeof(INST));
    pinst = *_pinst;
    if(!pinst) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return;
	}
    
    pinst->type = GetLongAttr(pPInst, "type");
    
    pinst->mnemonic = PyUnicode_AsUTF8AndSize(GetAttr(pPInst, "mnemonic"), &mnemonic_length);

    pinst->flags1 = GetLongAttr(pPInst, "flags1");
    pinst->flags2 = GetLongAttr(pPInst, "flags2");
    pinst->flags3 = GetLongAttr(pPInst, "flags3");
    pinst->modrm =  GetLongAttr(pPInst, "modrm");
}

/*
    Fill an OPERAND structure from the data in an "Operand" Python object.
*/
void FillOperandStruct(PyObject* pOperand, OPERAND *op)
{
    if(!pOperand || !op)
        return;
        
    op->type =           GetLongAttr(pOperand, "type");
    op->reg =            GetLongAttr(pOperand, "reg");
    op->basereg =        GetLongAttr(pOperand, "basereg");
    op->indexreg =       GetLongAttr(pOperand, "indexreg");
    op->scale =          GetLongAttr(pOperand, "scale");
    op->dispbytes =      GetLongAttr(pOperand, "dispbytes");
    op->dispoffset =     GetLongAttr(pOperand, "dispoffset");
    op->immbytes =       GetLongAttr(pOperand, "immbytes");
    op->immoffset =      GetLongAttr(pOperand, "immoffset");
    op->sectionbytes =   GetLongAttr(pOperand, "sectionbytes");
    op->section = (WORD) GetLongAttr(pOperand, "section");
    op->displacement =   GetLongAttr(pOperand, "displacement");
    op->immediate =      GetLongAttr(pOperand, "immediate");
    op->flags =          GetLongAttr(pOperand, "flags");
}

/*
    Fill an INSTRUCTION structure from the data in an "Instruction" Python object.
*/
void FillInstructionStruct(PyObject* pInstruction, INSTRUCTION *insn)
{
    insn->length =          GetLongAttr(pInstruction, "length");
    insn->type =            GetLongAttr(pInstruction, "type");
    insn->mode =            GetLongAttr(pInstruction, "mode");
    insn->opcode =   (BYTE) GetLongAttr(pInstruction, "opcode");
    insn->modrm =    (BYTE) GetLongAttr(pInstruction, "modrm");
    insn->sib =      (BYTE) GetLongAttr(pInstruction, "sib");
    insn->extindex =        GetLongAttr(pInstruction, "extindex");
    insn->fpuindex =        GetLongAttr(pInstruction, "fpuindex");
    insn->dispbytes =       GetLongAttr(pInstruction, "dispbytes");
    insn->immbytes =        GetLongAttr(pInstruction, "immbytes");
    insn->sectionbytes =    GetLongAttr(pInstruction, "sectionbytes");
    insn->flags =           GetLongAttr(pInstruction, "flags");
    FillOperandStruct(GetAttr(pInstruction, "op1"), &insn->op1);
    FillOperandStruct(GetAttr(pInstruction, "op2"), &insn->op2);
    FillOperandStruct(GetAttr(pInstruction, "op3"), &insn->op3);
    FillInstStruct(GetAttr(pInstruction, "ptr"), &insn->ptr);
}

/*
    Python counterpart of libdasm's "get_instruction"
*/
#define GET_INSTRUCTION_DOCSTRING                                               \
    "Decode an instruction from the given buffer.\n\n"                          \
    "Takes in a string containing the data to disassemble and the\nmode, "      \
    "either MODE_16 or MODE_32. Returns an Instruction object or \nNone if "    \
    "the instruction can't be disassembled."
    
PyObject* PyDAsmGetInstruction(PyObject* self, PyObject* args)
{
	PyObject *pBuffer, *pMode;
	INSTRUCTION insn;
	int size, mode;
	
	if(!args || PyObject_Length(args)!=2) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 2 expected: (data, mode)");
		return NULL;
	}
	
	pBuffer = PyTuple_GetItem(args, 0);
	if(!CheckObj(pBuffer)) {
        PyErr_SetString(PyExc_ValueError, "Can't get buffer from arguments");
    }
    
	pMode = PyTuple_GetItem(args, 1);
	if(!CheckObj(pMode)) {
        PyErr_SetString(PyExc_ValueError, "Can't get mode from arguments");
    }
    mode = PyLong_AsLong(pMode);

	ssize_t data_length;
    char* data;
	
	if(PyBytes_AsStringAndSize(pBuffer, &data, &data_length) == -1) {
		PyErr_SetString(PyExc_TypeError, "Error reading buffer!");
		return NULL;
	}
	
	size = get_instruction(&insn, (unsigned char*) data, mode);
    
    if(!size) {    
        Py_INCREF(Py_None);
        return Py_None;
    }

    return CreateInstructionObj(&insn);
}

/*
    Python counterpart of libdasm's "get_instruction_string"
*/
#define GET_INSTRUCTION_STRING_DOCSTRING                                    \
    "Transform an instruction object into its string representation.\n\n"   \
    "The function takes an Instruction object; its format, either \n"       \
    "FORMAT_INTEL or FORMAT_ATT and finally an offset (refer to \n"         \
    "libdasm for meaning). Returns a string representation of the \n"       \
    "disassembled instruction."
    
PyObject* PyDAsmGetInstructionString(PyObject* self, PyObject* args)
{
	PyObject* pInstruction, *pFormat, *pOffset, *pStr;
	INSTRUCTION insn;
	unsigned long int offset, format;
    
	if(!args || PyObject_Length(args)!=3) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 3 expected: (instruction, format, offset)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!CheckObj(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    if(pInstruction == Py_None) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    memset(&insn, 0, sizeof(INSTRUCTION));
    FillInstructionStruct(pInstruction, &insn);
    
	pFormat = PyTuple_GetItem(args, 1);
	if(!CheckObj(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
	pOffset = PyTuple_GetItem(args, 2);
	if(!CheckObj(pOffset)) {
        PyErr_SetString(PyExc_ValueError, "Can't get offset from arguments");
    }
    offset = PyLong_AsLong(pOffset);

    char* data = (char*) calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		free(insn.ptr);
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    if(!get_instruction_string(&insn, format, offset,
        data, INSTRUCTION_STR_BUFFER_LENGTH))
    {    
	    free(insn.ptr);
		free(data);
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    pStr = PyUnicode_FromStringAndSize(data, strlen(data));    
    free(insn.ptr);
    free(data);
    
    return pStr;
}

/*
    Python counterpart of libdasm's "get_mnemonic_string"
*/
#define GET_MNEMONIC_STRING_DOCSTRING                                       \
    "Transform an instruction object's mnemonic into its string representation.\n\n"    \
    "The function takes an Instruction object and its format, either \n"    \
    "FORMAT_INTEL or FORMAT_ATT. Returns a string representation of the \n" \
    "mnemonic."
    
PyObject* PyDAsmGetMnemonicString(PyObject* self, PyObject* args)
{
	PyObject* pInstruction, *pFormat, *pStr;
	INSTRUCTION insn;
	unsigned long int format;

	if(!args || PyObject_Length(args)!=2) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 3 expected: (instruction, format)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!CheckObj(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    FillInstructionStruct(pInstruction, &insn);
    
	pFormat = PyTuple_GetItem(args, 1);
	if(!CheckObj(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
    char* data = (char*) calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    get_mnemonic_string(&insn, format, data, INSTRUCTION_STR_BUFFER_LENGTH);
      
    pStr = PyUnicode_FromStringAndSize(data, strlen(data));
    free(data);
    
    return pStr;
}

/*
    Python counterpart of libdasm's "get_operand_string"
*/
#define GET_OPERAND_STRING_DOCSTRING                                        \
    "Transform an instruction object's operand into its string representation.\n\n"    \
    "The function takes an Instruction object; the operand index (0,1,2);\n"\
    " its format, either FORMAT_INTEL or FORMAT_ATT and finally an offset\n"\
    "(refer to libdasm for meaning). Returns a string representation of \n" \
    "the disassembled operand."
    
PyObject* PyDAsmGetOperandString(PyObject* self, PyObject* args)
{
	PyObject *pInstruction, *pFormat, *pOffset, *pOpIndex, *pStr;
	INSTRUCTION insn;
	unsigned long int offset, format, op_idx;
    
	if(!args || PyObject_Length(args)!=4) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 4 expected: (instruction, operand index, format, offset)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!CheckObj(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    memset(&insn, 0, sizeof(INSTRUCTION));
    FillInstructionStruct(pInstruction, &insn);
    
	pOpIndex = PyTuple_GetItem(args, 1);
	if(!CheckObj(pOpIndex)) {
        PyErr_SetString(PyExc_ValueError, "Can't get operand index from arguments");
    }
    op_idx = PyLong_AsLong(pOpIndex);
	
    pFormat = PyTuple_GetItem(args, 2);
	if(!CheckObj(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
	pOffset = PyTuple_GetItem(args, 3);
	if(!CheckObj(pOffset)) {
        PyErr_SetString(PyExc_ValueError, "Can't get offset from arguments");
    }
    offset = PyLong_AsLong(pOffset);

    char* data = (char*) calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    if(!get_operand_string(&insn, &(insn.op1)+op_idx,
        format, offset, data, INSTRUCTION_STR_BUFFER_LENGTH))
    {    
        free(data);
		Py_INCREF(Py_None);
        return Py_None;
    }
    
    pStr = PyUnicode_FromStringAndSize(data, strlen(data));
    free(data);
    
    return pStr;
}

/*
    Python counterpart of libdasm's "get_register_type"
*/
#define GET_REGISTER_TYPE_DOCSTRING                                         \
    "Get the type of the register used by the operand.\n\n"                 \
    "The function takes an Operand object and returns a Long representing\n"\
    "the type of the register."
    
PyObject* PyDAsmGetRegisterType(PyObject* self, PyObject* args)
{
	PyObject* pOperand;
    OPERAND op;

	if(!args || PyObject_Length(args)!=1) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 1 expected: (operand)");
		return NULL;
	}
	
	pOperand = PyTuple_GetItem(args, 0);
	if(!CheckObj(pOperand)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    memset(&op, 0, sizeof(OPERAND));
    FillOperandStruct(pOperand, &op);
        
    return PyLong_FromLong(get_register_type(&op));
}

//===========================================================
//Definitions of methods
//===========================================================

static PyMethodDef DAsmMethods[] = {
	{"get_instruction", PyDAsmGetInstruction, METH_VARARGS,
	GET_INSTRUCTION_DOCSTRING},
	{"get_instruction_string", PyDAsmGetInstructionString, METH_VARARGS,
	GET_INSTRUCTION_STRING_DOCSTRING},
	{"get_mnemonic_string", PyDAsmGetMnemonicString, METH_VARARGS,
	GET_MNEMONIC_STRING_DOCSTRING},
	{"get_operand_string", PyDAsmGetOperandString, METH_VARARGS,
	GET_OPERAND_STRING_DOCSTRING},
	{"get_register_type", PyDAsmGetRegisterType, METH_VARARGS,
	GET_REGISTER_TYPE_DOCSTRING},
	{NULL, NULL, 0, NULL}
};

static PyMethodDef InstMethods[] = {
	{NULL, NULL, 0, NULL}
};

static PyMethodDef InstructionMethods[] = {
	{NULL, NULL, 0, NULL}
};

static PyMethodDef OperandMethods[] = {
	{NULL, NULL, 0, NULL}
};

//===========================================================
//PyTypeObject definitions
//===========================================================

static PyTypeObject DAsmType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pydasm.DAsm",             /* tp_name */
    sizeof(PyDAsmObject), 	   /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)DAsm_dealloc,  /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "DAsm objects",            /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    DAsmMethods,               /* tp_methods */
    DAsmMembers,               /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)DAsm_init,       /* tp_init */
    0,                         /* tp_alloc */
    DAsm_new,                  /* tp_new */
};

static PyTypeObject InstType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pydasm.Inst",             	 	  /* tp_name */
    sizeof(PyInstObject), 	  		  /* tp_basicsize */
    0,                                /* tp_itemsize */
    (destructor)Inst_dealloc,         /* tp_dealloc */
    0,                         		  /* tp_print */
    0,                         		  /* tp_getattr */
    0,                                /* tp_setattr */
    0,                         	 	  /* tp_reserved */
    0,                         		  /* tp_repr */
    0,                         		  /* tp_as_number */
    0,                         		  /* tp_as_sequence */
    0,                         		  /* tp_as_mapping */
    0,                         		  /* tp_hash  */
    0,                         		  /* tp_call */
    0,                         		  /* tp_str */
    0,                         		  /* tp_getattro */
    0,                         		  /* tp_setattro */
    0,                         		  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   		  /* tp_flags */
    "Inst objects",            		  /* tp_doc */
    0,                         		  /* tp_traverse */
    0,                         		  /* tp_clear */
    0,                         		  /* tp_richcompare */
    0,                         		  /* tp_weaklistoffset */
    0,                         		  /* tp_iter */
    0,                         		  /* tp_iternext */
    InstMethods,              	  	  /* tp_methods */
    InstMembers,              	  	  /* tp_members */
    0,                         		  /* tp_getset */
    0,                         		  /* tp_base */
    0,                         		  /* tp_dict */
    0,                         		  /* tp_descr_get */
    0,                         		  /* tp_descr_set */
    0,                         		  /* tp_dictoffset */
    (initproc)Inst_init,       		  /* tp_init */
    0,                         		  /* tp_alloc */
    Inst_new,                  		  /* tp_new */
};

static PyTypeObject InstructionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pydasm.Instruction",             /* tp_name */
    sizeof(PyInstructionObject), 	  /* tp_basicsize */
    0,                                /* tp_itemsize */
    (destructor)Instruction_dealloc,  /* tp_dealloc */
    0,                         		  /* tp_print */
    0,                         		  /* tp_getattr */
    0,                                /* tp_setattr */
    0,                         	 	  /* tp_reserved */
    0,                         		  /* tp_repr */
    0,                         		  /* tp_as_number */
    0,                         		  /* tp_as_sequence */
    0,                         		  /* tp_as_mapping */
    0,                         		  /* tp_hash  */
    0,                         		  /* tp_call */
    0,                         		  /* tp_str */
    0,                         		  /* tp_getattro */
    0,                         		  /* tp_setattro */
    0,                         		  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   		  /* tp_flags */
    "Instruction objects",            /* tp_doc */
    0,                         		  /* tp_traverse */
    0,                         		  /* tp_clear */
    0,                         		  /* tp_richcompare */
    0,                         		  /* tp_weaklistoffset */
    0,                         		  /* tp_iter */
    0,                         		  /* tp_iternext */
    InstructionMethods,               /* tp_methods */
    InstructionMembers,               /* tp_members */
    0,                         		  /* tp_getset */
    0,                         		  /* tp_base */
    0,                         		  /* tp_dict */
    0,                         		  /* tp_descr_get */
    0,                         		  /* tp_descr_set */
    0,                         		  /* tp_dictoffset */
    (initproc)Instruction_init,       /* tp_init */
    0,                         		  /* tp_alloc */
    Instruction_new,                  /* tp_new */
};

static PyTypeObject OperandType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pydasm.Operand",             /* tp_name */
    sizeof(PyOperandObject),      /* tp_basicsize */
    0,                         	  /* tp_itemsize */
    (destructor)Operand_dealloc,  /* tp_dealloc */
    0,                         	  /* tp_print */
    0,                         	  /* tp_getattr */
    0,                         	  /* tp_setattr */
    0,                         	  /* tp_reserved */
    0,                         	  /* tp_repr */
    0,                         	  /* tp_as_number */
    0,                         	  /* tp_as_sequence */
    0,                         	  /* tp_as_mapping */
    0,                         	  /* tp_hash  */
    0,                         	  /* tp_call */
    0,                        	  /* tp_str */
    0,                         	  /* tp_getattro */
    0,                         	  /* tp_setattro */
    0,                         	  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   	  /* tp_flags */
    "Operand objects",            /* tp_doc */
    0,                         	  /* tp_traverse */
    0,                         	  /* tp_clear */
    0,                         	  /* tp_richcompare */
    0,                         	  /* tp_weaklistoffset */
    0,                         	  /* tp_iter */
    0,                         	  /* tp_iternext */
    OperandMethods,               /* tp_methods */
    OperandMembers,               /* tp_members */
    0,                         	  /* tp_getset */
    0,                         	  /* tp_base */
    0,                         	  /* tp_dict */
    0,                         	  /* tp_descr_get */
    0,                         	  /* tp_descr_set */
    0,                         	  /* tp_dictoffset */
    (initproc)Operand_init,       /* tp_init */
    0,                         	  /* tp_alloc */
    Operand_new,                  /* tp_new */
};

//===========================================================
//Build Python objects from C structs
//===========================================================

/*
    Create an "Inst" Python object from an INST structure.
*/
PyObject* CreateInstObj(INST *pinst)
{
	PyObject* pPInst = PyObject_CallObject((PyObject*) &InstType, NULL);
    
    if(!pPInst)
        return NULL;

    AssignAttr(pPInst, "type",      PyLong_FromLong(pinst->type));
    AssignAttr(pPInst, "mnemonic",  PyUnicode_FromString(pinst->mnemonic));
    AssignAttr(pPInst, "flags1",    PyLong_FromLong(pinst->flags1));
    AssignAttr(pPInst, "flags2",    PyLong_FromLong(pinst->flags2));
    AssignAttr(pPInst, "flags3",    PyLong_FromLong(pinst->flags3));
    AssignAttr(pPInst, "modrm",     PyLong_FromLong(pinst->modrm));
    
    return pPInst;
}

/*
    Create an "Operand" Python object from an OPERAND structure.
*/
PyObject* CreateOperandObj(OPERAND *op)
{
    PyObject* pOperand = PyObject_CallObject((PyObject*) &OperandType, NULL);
    
    if(!pOperand)
        return NULL;

    AssignAttr(pOperand, "type", 		 PyLong_FromLong(op->type));
    AssignAttr(pOperand, "reg", 		 PyLong_FromLong(op->reg));
    AssignAttr(pOperand, "basereg", 	 PyLong_FromLong(op->basereg));
    AssignAttr(pOperand, "indexreg", 	 PyLong_FromLong(op->indexreg));
    AssignAttr(pOperand, "scale", 		 PyLong_FromLong(op->scale));
    AssignAttr(pOperand, "dispbytes", 	 PyLong_FromLong(op->dispbytes));
    AssignAttr(pOperand, "dispoffset", 	 PyLong_FromLong(op->dispoffset));
    AssignAttr(pOperand, "immbytes", 	 PyLong_FromLong(op->immbytes));
    AssignAttr(pOperand, "immoffset", 	 PyLong_FromLong(op->immoffset));
    AssignAttr(pOperand, "sectionbytes", PyLong_FromLong(op->sectionbytes));
    AssignAttr(pOperand, "section", 	 PyLong_FromLong(op->section));
    AssignAttr(pOperand, "displacement", PyLong_FromLong(op->displacement));
    AssignAttr(pOperand, "immediate", 	 PyLong_FromLong(op->immediate));
    AssignAttr(pOperand, "flags",		 PyLong_FromLong(op->flags));
    
    return pOperand;
}

/*
    Create an "Instruction" Python object from an INSTRUCTION structure.
*/
PyObject* CreateInstructionObj(INSTRUCTION *insn)
{
    PyObject* pInstruction = PyObject_CallObject((PyObject*) &InstructionType, NULL);

    if(!pInstruction)
        return NULL;
    
    AssignAttr(pInstruction, "length", 		 	PyLong_FromLong(insn->length));
    AssignAttr(pInstruction, "type", 		 	PyLong_FromLong(insn->type));
    AssignAttr(pInstruction, "mode", 		 	PyLong_FromLong(insn->mode));
    AssignAttr(pInstruction, "opcode", 		 	PyLong_FromLong(insn->opcode));
    AssignAttr(pInstruction, "modrm", 		 	PyLong_FromLong(insn->modrm));
    AssignAttr(pInstruction, "sib", 		 	PyLong_FromLong(insn->sib));
    AssignAttr(pInstruction, "extindex", 	 	PyLong_FromLong(insn->extindex));
    AssignAttr(pInstruction, "fpuindex", 	 	PyLong_FromLong(insn->fpuindex));
    AssignAttr(pInstruction, "dispbytes", 	 	PyLong_FromLong(insn->dispbytes));
    AssignAttr(pInstruction, "immbytes", 	 	PyLong_FromLong(insn->immbytes));
    AssignAttr(pInstruction, "sectionbytes", 	PyLong_FromLong(insn->sectionbytes));
    AssignAttr(pInstruction, "op1", 		 	CreateOperandObj(&insn->op1));
    AssignAttr(pInstruction, "op2", 	     	CreateOperandObj(&insn->op2));
    AssignAttr(pInstruction, "op3", 		 	CreateOperandObj(&insn->op3));
    AssignAttr(pInstruction, "ptr", 		 	CreateInstObj(insn->ptr));
    AssignAttr(pInstruction, "flags", 		 	PyLong_FromLong(insn->flags));
    AssignAttr(pInstruction, "eflags_affected", PyLong_FromLong(insn->eflags_affected));
    AssignAttr(pInstruction, "eflags_used", 	PyLong_FromLong(insn->eflags_used));
        
    return pInstruction;
}

#define PYDASM_DESC "A libdasm Python 3 wrapper"

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"pydasm",  			 /* m_name */
	PYDASM_DESC,  		 /* m_doc */
	-1,                  /* m_size */
	NULL,    	 		 /* m_methods */
	NULL,                /* m_reload */
	NULL,                /* m_traverse */
	NULL,                /* m_clear */
	NULL,                /* m_free */
};

/*
    Init the module, set constants.
*/
PyMODINIT_FUNC PyInit_pydasm(void)
{
    PyObject* m;
	
	if(PyType_Ready(&DAsmType) < 0 || PyType_Ready(&InstType) < 0 || 
	   PyType_Ready(&InstructionType) < 0 || PyType_Ready(&OperandType) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
	if (NULL == m)
		return NULL;
	
    AssignAttr(m, "FORMAT_ATT", PyLong_FromLong(0));
    AssignAttr(m, "FORMAT_INTEL", PyLong_FromLong(1));

    AssignAttr(m, "MODE_16", PyLong_FromLong(1));
    AssignAttr(m, "MODE_32", PyLong_FromLong(0));
    
    for(int i = 0; instruction_types[i]; i++)
        AssignAttr(m, instruction_types[i], PyLong_FromLong(i));
    
    for(int i = 0; operand_types[i]; i++)
        AssignAttr(m, operand_types[i], PyLong_FromLong(i));

    for(int i = 0; registers[i]; i++)
        AssignAttr(m, registers[i], PyLong_FromLong(i));
        
    for(int i = 0; register_types[i]; i++)
        AssignAttr(m, register_types[i], PyLong_FromLong(i+1));
	
	Py_INCREF(&DAsmType);
	PyModule_AddObject(m, "DAsm", (PyObject*) &DAsmType);

	Py_INCREF(&InstType);
	PyModule_AddObject(m, "Inst", (PyObject*) &InstType);
	
	Py_INCREF(&InstructionType);
	PyModule_AddObject(m, "Instruction", (PyObject*) &InstructionType);
	
	Py_INCREF(&OperandType);
	PyModule_AddObject(m, "Operand", (PyObject*) &OperandType);
	
	return m;
}


int main(int agrc, char* argv[]) {
	wchar_t* pName = Py_DecodeLocale(argv[0], NULL);
    if (NULL == pName) {
        fprintf(stderr, "Fatal error: cannot decode argv[0]\n");
        exit(1);
    }
	
	PyImport_AppendInittab("pydasm", PyInit_pydasm);
	
	Py_SetProgramName(pName);
	
	Py_Initialize();
	
	PyInit_pydasm();
	
	PyMem_RawFree(pName);

	return 0;
}
