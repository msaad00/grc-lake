"""Generic cursor-pagination iterator.

Different APIs cursor differently (Okta ``Link: rel="next"``, Jira
``startAt``/``total``, AWS ``NextToken``). :func:`paginate` factors out the loop
so a runner supplies three small callables and gets a flat item stream, with a
page cap as a runaway guard.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from typing import Any, TypeVar

Page = TypeVar("Page")
Item = TypeVar("Item")


class IncompleteCollectionError(RuntimeError):
    """A page budget was exhausted. Yielded items are not a complete collection.

    The cursor is available to the caller for explicit resumption, but is never
    interpolated in the error message because provider cursors may be sensitive.
    """

    def __init__(self, *, cursor: Any, pages_fetched: int) -> None:
        super().__init__(f"collection incomplete: page budget exhausted after {pages_fetched} pages")
        self.cursor = cursor
        self.pages_fetched = pages_fetched


def next_link_url(link_header: str) -> str | None:
    """Extract the ``rel="next"`` URL from an RFC 8288 ``Link`` response header."""
    for part in link_header.split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url = segments[0].strip().lstrip("<").rstrip(">").strip()
        rels = "".join(segments[1:]).replace(" ", "").replace('"', "")
        if "rel=next" in rels and url:
            return url
    return None


def paginate(
    fetch_page: Callable[[Any | None], Page],
    extract_items: Callable[[Page], Iterable[Item]],
    next_cursor: Callable[[Page], Any | None],
    *,
    start_cursor: Any | None = None,
    max_pages: int = 1000,
) -> Iterator[Item]:
    """Yield items across pages until ``next_cursor`` returns None; raise if the cap truncates collection.

    ``fetch_page(cursor)`` returns a page; ``extract_items(page)`` its rows;
    ``next_cursor(page)`` the next cursor or None when exhausted.
    """
    if type(max_pages) is not int or max_pages < 1:
        raise ValueError("max_pages must be a positive integer")
    cursor = start_cursor
    for _ in range(max_pages):
        page = fetch_page(cursor)
        yield from extract_items(page)
        cursor = next_cursor(page)
        if cursor is None:
            return

    raise IncompleteCollectionError(cursor=cursor, pages_fetched=max_pages)
