#!/usr/bin/env python
# coding: utf-8
#
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
"""
A datastructure and associated functions for interacting with stack traces
and other stack trace like things

"""

import enum
import functools
import re
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union
import pathlib
import random
import sys
import matplotlib.pyplot as plt  # type: ignore

# pylint: disable=wrong-import-position, wrong-import-order
import anytree  # type: ignore


# This is needed for reasons I only mostly understand to get python to pickup
# changes to modules. You need to reload if you change anytree, and it's easier
# to do this than constantly restart the jupyter kernel
import importlib  # pylint: disable=wrong-import-position

importlib.reload(anytree)


class FileFormat(enum.Enum):
    """The different sources of data, corresponding to the different parsers"""

    DTRACE = enum.auto()


class TraceElement:  # pylint: disable=too-few-public-methods
    """An abstract base class for all traces, irrespective of source"""

    def __init__(self, stack: List[str], num_points: int) -> None:
        # Stack is root-first.
        # i.e. a(b(c())) would be [a, b, c] not the other way around
        self.stack = stack
        self.num_points = num_points

    def __str__(self) -> str:
        return f"Num_Points {self.num_points} for stack:\n" + "\n".join(self.stack)

    @staticmethod
    def parse_dtrace(text: str, ignore_leading: int = 3) -> List["TraceElement"]:
        """Parse a DTrace output file.
        By default DTrace puts a 3 lines we don't need at the top
        of the file, configured with ignore_leading"""
        # DTrace format is a stack trace, one line per frame,
        # followed by an int, followed by a blank line.
        # We want to end up with a list of (lists of lines)
        # where each sublist is a single stack trace plus it's int

        # Ideally we would split it into lines, and then split
        # the resulting list on empty lines, however we can't
        # because Python lacks an easy way to split lists
        # So instead we split on "\n\n" which is an empty line and the
        # surrounding line breaks.

        # However we might have \r\n line endings, or random whitespace so
        # first we use the builtin splitlines, strip whitespace, then
        # rejoin them with \n to ensure they're uniform
        # We also get rid of the leading lines we don't want at the same time
        lines = text.splitlines()
        lines = lines[ignore_leading:]
        lines = list(map(lambda s: s.strip(), lines))
        joined_lines = "\n".join(lines)

        stack_strings = joined_lines.split("\n\n")
        stacks = [s.splitlines() for s in stack_strings]

        # A stacktrace line is going to contain at least one character that
        # isn't a digit, whereas the final line will only contain digits
        # Verify this here as a basic check that we parsed correctly.

        for stack in stacks:
            for line in stack[:-1]:
                if not re.search(r"[^0-9]", line):
                    raise ValueError(
                        f"Parsing Failure on line {line} in stacktrace"
                        + f"{str(stack)}.\nExpected at least one non-digit"
                    )

            if not re.match(r"^[0-9]*$", stack[-1]):
                raise ValueError(
                    f"Parsing Failure on line {stack[:-1]} in stacktrace"
                    + f"{str(stack)}.\nFinal line should only contain digits"
                )

        traces = []
        for stack in stacks:
            # Last element is the number, and reverse it because dtrace prints
            # leaf first and root last
            trace_stack = stack[:-1]
            root_first = trace_stack[::-1]
            traces.append(TraceElement(root_first, int(stack[-1])))

        return traces

    @staticmethod
    def from_pydtrace_dict(
        stacktrace_dict: Dict[Tuple[Tuple[Any]], int]
    ) -> List["TraceElement"]:
        """Parse the PyDTrace output format
        It outputs a dictionary mapping (tuple of leaf-first stack frames)
        to ints
        """
        # The Dict that the python dtrace module gives us is in the form
        # (Tuple of stack frames -> Number of traces)
        # We want to turn this into a list of TraceElement objects
        # Our Tuple of stack frames is leaf-first, so we need to reverse it.

        traces = []
        for (key, val) in stacktrace_dict.items():
            # Convert to list and reverse to get root-first order
            list_of_frames = list(key)[::-1]

            tidied_frames = []
            for frame in list_of_frames:
                # Based on a very small sample size, it looks like these are
                # all of the form (byte-string, byte-string), where the first
                # byte-string is b'kernel' or similar and the second is the
                # actual function

                # If this assumption fails, just fall back on stringifying
                fallback = str(frame)

                try:
                    assert isinstance(frame, tuple)
                    parts = [b.decode("utf-8") for b in list(frame)]

                    ignorable_prefixes = [
                        "kernel",
                    ]
                    if parts[0] in ignorable_prefixes:
                        parts = parts[1:]
                    tidied_frames.append("::".join(parts))

                # We just catch exception because a bunch of things can
                # go wrong, e.g. there is no parts[0]
                # and it's easier to just attempt things than check every
                # single possibility
                except Exception:  # pylint: disable=broad-except
                    tidied_frames.append(fallback)
                    continue

            traces.append(TraceElement(tidied_frames, val))

        return traces


class StackTree(anytree.node.NodeMixin):
    """The tree representation that flame graphs use"""

    def __init__(self, name: str, children: List["StackTree"], num_points: int) -> None:
        super().__init__()
        self.name = name
        children.sort(key=lambda c: c.name)
        self.children = children
        self.num_points = num_points

    @staticmethod
    def from_trace(
        trace_list: List[TraceElement], name: Optional[str] = None, skip_level: int = 0
    ) -> "StackTree":
        """Parse a list of traces into a StackTree"""
        children: Dict[str, List["TraceElement"]] = {}
        for trace in trace_list:
            if len(trace.stack) <= skip_level:
                continue
            child_name = trace.stack[skip_level]
            if child_name not in children:
                children[child_name] = []
            children[child_name].append(trace)

        child_nodes = []
        for child_name in sorted(children.keys()):
            child_nodes.append(
                StackTree.from_trace(
                    children[child_name], name=child_name, skip_level=skip_level + 1
                )
            )

        if name is None:
            name = "all"

        num_points = functools.reduce(
            lambda total, t: total + t.num_points, trace_list, 0
        )
        return StackTree(name, child_nodes, num_points)

    def zoom(self, function_regex: str) -> "StackTree":
        """Zoom in on a subtree. Returns the first (breadth first) subtree
        who's name contains something that matches `function_regex`"""
        matching_nodes: Iterator["StackTree"] = anytree.LevelOrderIter(
            self, filter_=lambda n: re.search(function_regex, n.name) is not None
        )
        return next(matching_nodes)

    def filter(self, filter_func: Callable[["StackTree"], bool]) -> "StackTree":
        """Filter the tree, keeping only nodes for which
        filter_func(node) is True"""
        filtered_tree: "StackTree" = anytree.modifiers.tree_filter(
            self,
            filter_func,
        )
        return filtered_tree

    def __str__(self) -> str:
        lines = []
        for pre, _, node in anytree.RenderTree(self):
            lines.append(f"{pre}{node.name} ({node.num_points})")
        return "\n".join(lines)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        if self.name != other.name:
            return False

        if self.num_points != other.num_points:
            return False

        if len(self.children) != len(other.children):
            return False

        for (child1, child2) in zip(self.children, other.children):
            if child1 != child2:
                return False

        return True

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class Flamegraph:
    """A subset of a flamegraph which can be plotted"""

    def __init__(
        self,
        name: str,
        children: List["Flamegraph"],
        width: int,
        extra: Optional[Any] = None,
    ) -> None:
        self.name = name
        self.children = children
        self.depth = 0
        self.width = width
        self.extra = extra
        self.indent_from_root = 0
        self.colour = None

    @staticmethod
    def from_stack_tree(stack_tree: StackTree, scale_factor: int = 1) -> "Flamegraph":
        """Parse a Stacktree and generate flamegraph specific data"""
        ret = Flamegraph._from_stack_tree_internal(stack_tree, scale_factor)
        # TODO - this should probably be an exception
        assert ret is not None, "Scale Factor is too high, nothing to plot"
        return ret

    @staticmethod
    def _from_stack_tree_internal(
        stack_tree: StackTree, scale_factor: int = 1
    ) -> Optional["Flamegraph"]:
        """Parse a Stacktree and generate flamegraph specific data
        This is an internal function which can return None if the flamegraph
        is empty"""
        if stack_tree.num_points < scale_factor:
            return None
        child_flame_graphs: List["Flamegraph"] = [
            child_graph
            for c in stack_tree.children
            if (child_graph := Flamegraph._from_stack_tree_internal(c)) is not None
        ]
        return Flamegraph(
            stack_tree.name, child_flame_graphs, stack_tree.num_points // scale_factor
        )

    def calculate_indents(self, indent_from_root: int = 0, depth: int = 0) -> None:
        """Calculate the x indent of this graph subset"""
        self.indent_from_root = indent_from_root
        self.depth = depth

        if len(self.children) == 0:
            return

        child_width = sum(child.width for child in self.children)
        num_children = len(self.children)
        blank_space = self.width - child_width
        num_gaps = num_children + 1  # 1 gap before each child, plus 1 at the end

        gap_sizes = [blank_space // num_gaps] * num_gaps

        remaining_space = blank_space - sum(gap_sizes)

        # Make the outside gaps larger
        gap_sizes[0] += remaining_space // 2
        gap_sizes[-1] += remaining_space // 2

        if (remaining_space % 2) == 1:
            gap_sizes[-1] += 1

        assert sum(gap_sizes) == blank_space

        running_child_indent = 0
        for (i, child) in enumerate(self.children):
            running_child_indent += gap_sizes[i]
            child.calculate_indents(indent_from_root + running_child_indent, depth + 1)
            running_child_indent += child.width

    def plot(self, fig: Any, ax: Any) -> None:
        """Plot the flamegraph onto the given axis"""
        self.calculate_indents()
        bars = self.get_bars()
        colours = Flamegraph.get_colours(bars)

        ax.set_facecolor("navajowhite")

        # https://stackoverflow.com/a/19306776/11751242
        plot_width = (
            ax.get_window_extent().transformed(fig.dpi_scale_trans.inverted()).width
            * fig.dpi
        )

        # You may also need to tweak this
        characters_per_line = plot_width / 8

        for (i, (bar, colour_list)) in enumerate(zip(bars, colours)):
            ax.broken_barh(
                [b["bar"] for b in bar],
                (i, 1),
                facecolors=colour_list,
                #                edgecolors='white',
            )
            for bar_segment in bar:
                (start, width) = bar_segment["bar"]
                bar_max_chars = characters_per_line * (width / self.width)
                if len(bar_segment["name"]) > bar_max_chars:
                    continue
                ax.text(
                    x=start + width / 2,
                    y=i + 0.5,
                    s=bar_segment["name"],
                    ha="center",
                    va="center",
                    color="black",
                )

        ax.set_xlim(0, self.width)
        ax.set_ylim(0, len(bars) + 1)

        # Get rid of the labels as they're meaningless on a flamegraph
        ax.set_xticks([])
        ax.set_yticks([])

    def get_bars(self) -> List[List[Dict[str, Any]]]:
        """Condense the tree into a single plot

        The matplotlib plot is plotted 1 row at a time, so we need to group
        the entire tree by stack depth.

        We then recursively merge the groups at each level
        until we get to the root
        """
        subgraph: List[List[Dict[str, Any]]] = []
        for i in range(self.max_depth() - self.depth + 1):
            subgraph.append([])
        subgraph[0].append(
            {"bar": (self.indent_from_root, self.width), "name": self.name}
        )

        for child in self.children:
            child_subgraph = child.get_bars()
            for (i, bars) in enumerate(child_subgraph):
                subgraph[i + 1].extend(bars)

        return subgraph

    def max_depth(self) -> int:
        """Get the maximum stack depth of the tree"""
        if len(self.children) == 0:
            return self.depth

        return max(c.max_depth() for c in self.children)

    @staticmethod
    def get_colours(
        bars: List[List[Dict[str, Any]]]
    ) -> List[List[Tuple[float, float, float]]]:
        """Given a the bars for this flamegraph, return an equivalently shaped
        set of colours to colour them in"""
        total_bars = 0
        hashable_bars = []
        for row in bars:
            total_bars += len(row)
            hashable_bars.append((b["bar"], b["name"]) for b in row)

        all_colours = [(1.0, val / total_bars, 0.0) for val in range(total_bars)]

        # Ideally it would be done intelligently so that bars were always different from
        # the adjacent ones, but a. I don't understand colour theory and b. I'm in a hurry
        # so just randomise for now. But we seeded the prng so it's deterministic
        random.seed(hash(tuple(hashable_bars)))
        random.shuffle(all_colours)

        shaped_colours = []
        for row in bars:
            shaped_colours.append(all_colours[: len(row)])
            all_colours = all_colours[len(row) :]

        return shaped_colours


def main(filename: Union[str, pathlib.Path], file_format: FileFormat) -> None:
    """Main function"""

    _ = file_format  # TODO: currently we assume DTrace
    with open(filename, encoding="utf-8") as f:
        lines = f.read()
    trace = TraceElement.parse_dtrace(lines)

    stack_tree = StackTree.from_trace(trace)
    flame_graph = Flamegraph.from_stack_tree(stack_tree)

    fig, ax = plt.subplots(
        figsize=(12, 8),
        dpi=100,
    )
    flame_graph.plot(fig, ax)
    plt.show()


if __name__ == "__main__":
    main(
        sys.argv[1],
        FileFormat.DTRACE,
    )
