#!/usr/bin/env ruby
# Copyright (c) 2006       Matt Miller skape <mmiller / hick.org>
# Copyright (c) 2004-2007  Jarkko Turkulainen <jt / nologin.org> <turkja / github.com>
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1) Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2) Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

$:.unshift(File.join(File.dirname(__FILE__)))

require 'test/unit'
require 'dasm'

class Dasm::UnitTest < Test::Unit::TestCase
	def test_mode
		d = Dasm.new

		assert_equal(32, d.mode)
		assert_equal(true, d.set_mode(16))
		assert_equal(16, d.mode)
		assert_equal(true, d.set_mode(32))
		assert_equal(32, d.mode)
	end

	def test_disassemble
		d   = Dasm.new
		b1  = "\x41\x42"
		ary = d.disassemble(b1)

		assert_not_nil(ary)

		inst = ary[0]

		assert_not_nil(inst)
		assert_kind_of(Dasm::Instruction, inst)
		assert_equal(1, inst.length)
		assert_equal(Dasm::Instruction::Type::INC, inst.type)
		assert_equal(32, inst.mode)
		assert_equal(0x41, inst.opcode)
		assert_nil(inst.modrm)
		assert_nil(inst.sib)
		assert_equal(0, inst.dispbytes)
		assert_equal(0, inst.immbytes)
		assert_equal(0, inst.sectionbytes)
		assert_equal("\x41", inst.raw)
		assert_equal("inc ecx", inst.to_s);
		d.set_format("att")
		assert_equal("inc %ecx", inst.to_s);
		assert_equal(Dasm::EFL_OF | Dasm::EFL_SF | Dasm::EFL_ZF | Dasm::EFL_AF | Dasm::EFL_PF, inst.eflags_affected)
		assert_equal(0, inst.eflags_used)

		assert_kind_of(Dasm::Instruction, d.disassemble_one(b1))
	end

	def test_operand
		d   = Dasm.new
		b1  = "\xc7\x44\x24\x04\x78\x56\x34\x12\x41"
		ary = d.disassemble(b1)

		assert_not_nil(ary)

		inst1 = ary[0]
		inst2 = ary[1]

		# inst1: mov dword [esp+0x4],0x12345678
		assert_not_nil(inst1.op1)
		assert_not_nil(inst1.op2)
		assert_nil(inst1.op3)
		assert_equal(Dasm::Operand::Type::Memory, inst1.op1.type)
		assert_equal(Dasm::Operand::Type::Immediate, inst1.op2.type)
		assert_equal(Dasm::Register::ESP, inst1.op1.basereg)
		assert_equal(4, inst1.op1.displacement)
		assert_equal(0x12345678, inst1.op2.immediate)
		assert_equal("mov dword [esp+0x4],0x12345678", inst1.to_s)

		# inst2: inc ecx
		assert_not_nil(inst2.op1)
		assert_nil(inst2.op2)
		assert_nil(inst2.op3)
		assert_equal(Dasm::Register::ECX, inst2.op1.reg)
		assert_equal(Dasm::RegisterType::General, inst2.op1.regtype)

		d.disassemble(b1) { |inst, off|
			if (off == 0)
				assert_equal("mov dword [esp+0x4],0x12345678", inst.to_s)
			else
				assert_equal("inc ecx", inst.to_s)
			end
		}
	end

end
