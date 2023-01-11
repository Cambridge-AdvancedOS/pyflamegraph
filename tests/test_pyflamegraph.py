# -
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2022-23 Rosie Baish
#
# This software was developed by the University of Cambridge Computer
# Laboratory (Department of Computer Science and Technology) under Office of
# Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
# with Secure Hardware (SWISH)").
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import pathlib

import pyflamegraph


def test_simple_dtrace():
    """A basic test to check that an artifical example in simple.dtrace
    gives the correct result"""
    with open(pathlib.Path("tests") / "test_cases" / "simple.dtrace", "r") as f:
        test_data = f.read()

    trace = pyflamegraph.TraceElement.parse_dtrace(test_data)
    stacktree = pyflamegraph.StackTree.from_trace(trace)

    ST = pyflamegraph.StackTree
    desired_output = ST(
        "all",
        [
            ST(
                "root_func",
                [
                    ST(
                        "branch_a",
                        [
                            ST("leaf_1", [], 3),
                            ST("leaf_2", [], 1),
                        ],
                        6,
                    ),
                    ST("branch_b", [ST("leaf_3", [], 20)], 20),
                ],
                26,
            )
        ],
        26,
    )

    print(stacktree)
    print(desired_output)

    assert stacktree == desired_output


def test_simple_pydtrace():
    """The same trace as simple.dtrace, but in the pydtrace format"""

    input_dict = {
        (
            (b"leaf_1",),
            (b"branch_a",),
            (b"root_func",),
        ): 3,
        (
            (b"leaf_2",),
            (b"branch_a",),
            (b"root_func",),
        ): 1,
        (
            (b"branch_a",),
            (b"root_func",),
        ): 2,
        (
            (b"leaf_3",),
            (b"branch_b",),
            (b"root_func",),
        ): 20,
    }

    trace = pyflamegraph.TraceElement.from_pydtrace_dict(input_dict)
    stacktree = pyflamegraph.StackTree.from_trace(trace)

    ST = pyflamegraph.StackTree
    desired_output = ST(
        "all",
        [
            ST(
                "root_func",
                [
                    ST(
                        "branch_a",
                        [
                            ST("leaf_1", [], 3),
                            ST("leaf_2", [], 1),
                        ],
                        6,
                    ),
                    ST("branch_b", [ST("leaf_3", [], 20)], 20),
                ],
                26,
            )
        ],
        26,
    )

    print(stacktree)
    print(desired_output)

    assert stacktree == desired_output
