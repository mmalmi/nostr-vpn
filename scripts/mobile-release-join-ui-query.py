#!/usr/bin/env python3
"""Query Android's public UIAutomator XML for the Release join gate."""

import argparse
import html
import re
import sys
import xml.etree.ElementTree as ET


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("xml")
    result.add_argument(
        "kind",
        choices=(
            "resource",
            "description",
            "text",
            "checkbox-label",
            "resource-prefix",
            "description-prefix",
        ),
    )
    result.add_argument("expected")
    result.add_argument(
        "output",
        choices=(
            "center",
            "safe-center",
            "visible-center",
            "description",
            "text",
            "count",
            "width",
            "enabled",
            "checked",
        ),
    )
    return result


def resource_matches(actual: str, expected: str) -> bool:
    return actual == expected or actual.endswith(f":id/{expected}") or actual.endswith(f"/{expected}")


def matches(node: ET.Element, kind: str, expected: str) -> bool:
    if kind == "resource":
        return resource_matches(node.attrib.get("resource-id", ""), expected)
    if kind == "resource-prefix":
        actual = node.attrib.get("resource-id", "")
        short = actual.rsplit("/", 1)[-1]
        return short.startswith(expected)
    if kind == "text":
        return html.unescape(node.attrib.get("text", "")) == expected
    actual = html.unescape(node.attrib.get("content-desc", ""))
    if kind == "description-prefix":
        return actual.startswith(expected)
    return actual == expected


def center(node: ET.Element) -> str:
    left, top, right, bottom = bounds(node)
    return f"{(left + right) // 2} {(top + bottom) // 2}"


def bounds(node: ET.Element) -> tuple[int, int, int, int]:
    bounds = node.attrib.get("bounds", "")
    match = re.fullmatch(r"\[(-?\d+),(-?\d+)]\[(-?\d+),(-?\d+)]", bounds)
    if not match:
        raise ValueError(f"invalid bounds: {bounds}")
    left, top, right, bottom = map(int, match.groups())
    if right <= left or bottom <= top:
        raise ValueError(f"empty bounds: {bounds}")
    return left, top, right, bottom


def viewport(root: ET.Element, node: ET.Element) -> tuple[int, int, int, int, bool]:
    parents = {child: parent for parent in root.iter() for child in parent}
    parent = parents.get(node)
    while parent is not None:
        if (
            parent.get("scrollable") == "true"
            or parent.get("class", "").endswith("ScrollView")
        ):
            return (*bounds(parent), True)
        parent = parents.get(parent)
    node_box = bounds(node)
    boxes: list[tuple[int, int, int, int]] = []
    for candidate in root.iter("node"):
        try:
            box = bounds(candidate)
        except ValueError:
            continue
        if box != node_box and (
            box[0] <= node_box[0]
            and box[1] <= node_box[1]
            and box[2] >= node_box[2]
            and box[3] >= node_box[3]
        ):
            boxes.append(box)
    if not boxes:
        raise ValueError("hierarchy has no valid viewport")
    return (*max(boxes, key=lambda box: (box[2] - box[0]) * (box[3] - box[1])), False)


def main() -> int:
    args = parser().parse_args()
    root = ET.parse(args.xml).getroot()
    if args.kind == "checkbox-label":
        # Compose exposes each checkbox immediately before its label, with
        # multiple settings flattened into the same parent accessibility node.
        found = []
        for parent in root.iter("node"):
            children = list(parent)
            for previous, label in zip(children, children[1:]):
                if (
                    matches(label, "text", args.expected)
                    and previous.get("checkable") == "true"
                ):
                    found.append(previous)
    else:
        found = [node for node in root.iter("node") if matches(node, args.kind, args.expected)]
    if args.output == "count":
        print(len(found))
        return 0
    if not found:
        return 1
    node = found[0]
    if args.output in ("center", "safe-center", "visible-center"):
        if args.output in ("safe-center", "visible-center"):
            try:
                viewport_left, viewport_top, viewport_right, viewport_bottom, scroll_viewport = viewport(
                    root, node
                )
            except ValueError:
                return 1
            safe_top = viewport_top if scroll_viewport else viewport_top + 200
            safe_bottom = viewport_bottom if scroll_viewport else viewport_bottom - 300
            left, top, right, bottom = bounds(node)
            if args.output == "visible-center":
                left, top = max(left, viewport_left), max(top, safe_top)
                right = min(right, viewport_right)
                bottom = min(bottom, safe_bottom)
                if right <= left or bottom - top < 48:
                    return 1
                print(f"{(left + right) // 2} {(top + bottom) // 2}")
                return 0
            if (
                left < viewport_left
                or top < viewport_top
                or right > viewport_right
                or bottom > safe_bottom
            ):
                return 1
        print(center(node))
    elif args.output == "width":
        left, _, right, _ = bounds(node)
        print(right - left)
    elif args.output == "description":
        print(html.unescape(node.attrib.get("content-desc", "")))
    elif args.output in ("enabled", "checked"):
        print(node.attrib.get(args.output, "false").lower())
    else:
        print(html.unescape(node.attrib.get("text", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
