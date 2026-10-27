"""Strict AST-based static admission validator for candidate Python scripts.

IMPORTANT SECURITY BOUNDARY:
- Static AST validation is defense-in-depth only and is NOT a replacement for
  isolated Linux container sandboxing (SEC01-SEC10).
- Passing AST validation never authorizes code execution on the host or inside
  FastAPI/Streamlit processes.
- Candidate code is parsed as inert text with `ast.parse(..., mode="exec")` and
  is never compiled into bytecode, imported, or executed.
"""

import ast
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import re
from typing import Literal
import unicodedata

from backend.inference import (
     GeneratedCodeCandidate,
    MAX_CODE_BYTES,
    MAX_CODE_LINES,
    _ALLOWED_CODE_IMPORTS,
)


MAX_AST_NODES = 2500
MAX_AST_DEPTH = 40
MAX_STRING_LITERAL_CHARS = 512
MAX_INT_LITERAL_ABS = 10**15

ALLOWED_AST_MODULES: frozenset[str] = frozenset({
    "math",
    "statistics",
    "decimal",
    "datetime",
    "json",
    "pandas",
    "numpy",
    "matplotlib",
    "matplotlib.pyplot",
})

ALLOWED_IMPORT_ALIASES: dict[str, frozenset[str | None]] = {
    "math": frozenset({None}),
    "statistics": frozenset({None}),
    "decimal": frozenset({None}),
    "datetime": frozenset({None}),
    "json": frozenset({None}),
    "pandas": frozenset({None, "pd"}),
    "numpy": frozenset({None, "np"}),
    "matplotlib": frozenset({None}),
    "matplotlib.pyplot": frozenset({"plt"}),
}

FORBIDDEN_CALL_NAMES: frozenset[str] = frozenset({
    "eval",
    "exec",
    "compile",
    "open",
    "input",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "hasattr",
    "globals",
    "locals",
    "vars",
    "dir",
    "type",
    "super",
    "object",
    "id",
    "hash",
    "memoryview",
    "bytearray",
    "bytes",
    "breakpoint",
    "help",
    "exit",
    "quit",
    "chr",
    "ord",
    "format",
    "repr",
    "ascii",
    "callable",
    "classmethod",
    "staticmethod",
    "property",
    "iter",
    "next",
    "aiter",
    "anext",
})

ALLOWED_BARE_CALLS: frozenset[str] = frozenset({
    "abs",
    "bool",
    "dict",
    "float",
    "int",
    "len",
    "list",
    "max",
    "min",
    "round",
    "str",
    "sum",
    "tuple",
})

FORBIDDEN_ATTRIBUTE_NAMES: frozenset[str] = frozenset({
    # Dynamic evaluation / query execution in pandas or stdlib
    "eval",
    "query",
    "pipe",
    "apply",
    "applymap",
    "map",
    "transform",
    # Filesystem, network, clipboard, SQL, pickle, and external serialization I/O
    "read_csv",
    "read_excel",
    "read_json",
    "read_sql",
    "read_sql_query",
    "read_sql_table",
    "read_parquet",
    "read_pickle",
    "read_fwf",
    "read_html",
    "read_xml",
    "read_clipboard",
    "read_feather",
    "read_hdf",
    "read_orc",
    "read_sas",
    "read_spss",
    "read_stata",
    "read_table",
    "read_gbq",
    "to_csv",
    "to_excel",
    "to_json",
    "to_sql",
    "to_pickle",
    "to_parquet",
    "to_hdf",
    "to_feather",
    "to_clipboard",
    "to_html",
    "to_xml",
    "to_latex",
    "to_markdown",
    "to_orc",
    "to_stata",
    "to_gbq",
    "load",
    "loads",
    "dump",
    "fromfile",
    "tofile",
    "save",
    "savez",
    "savez_compressed",
    "loadtxt",
    "genfromtxt",
    "savetxt",
    "memmap",
    "DataSource",
    "system",
    "popen",
    "spawn",
    "fork",
    "execv",
    "execve",
    "ctypes",
})

ALLOWED_ATTRIBUTE_NAMES: frozenset[str] = frozenset({
    # pandas / DataFrame / Series safe deterministic operations
    "DataFrame",
    "Series",
    "from_records",
    "loc",
    "iloc",
    "copy",
    "dropna",
    "fillna",
    "groupby",
    "agg",
    "aggregate",
    "reset_index",
    "sort_values",
    "head",
    "tail",
    "rename",
    "astype",
    "isin",
    "notna",
    "isna",
    "isnull",
    "notnull",
    "to_dict",
    "tolist",
    "values",
    "columns",
    "index",
    "empty",
    "shape",
    "count",
    "sum",
    "mean",
    "median",
    "min",
    "max",
    "std",
    "where",
    "replace",
    "round",
    # numpy safe constants/helpers
    "nan",
    "isnan",
    "isfinite",
    "array",
    "float64",
    "int64",
    # math / statistics / decimal / datetime / json safe helpers
    "dumps",
    "fsum",
    "stdev",
    "Decimal",
    "date",
    "datetime",
    "fromisoformat",
    "isoformat",
    # basic container methods
    "get",
    "items",
    "keys",
    "values",
    "append",
    "extend",
    "strip",
})

_ALLOWED_STATEMENT_NODES: tuple[type[ast.AST], ...] = (
    ast.Module,
    ast.Import,
    ast.ImportFrom,
    ast.FunctionDef,
    ast.Assign,
    ast.AnnAssign,
    ast.AugAssign,
    ast.Return,
    ast.If,
    ast.For,
    ast.Expr,
    ast.Pass,
    ast.Break,
    ast.Continue,
)

_ALLOWED_EXPRESSION_AND_SUPPORT_NODES: tuple[type[ast.AST], ...] = (
    ast.Name,
    ast.Load,
    ast.Store,
    ast.Constant,
    ast.Tuple,
    ast.List,
    ast.Dict,
    ast.Set,
    ast.ListComp,
    ast.DictComp,
    ast.comprehension,
    ast.Subscript,
    ast.Slice,
    ast.Attribute,
    ast.Call,
    ast.BinOp,
    ast.UnaryOp,
    ast.BoolOp,
    ast.Compare,
    ast.IfExp,
    ast.keyword,
    ast.arguments,
    ast.arg,
    ast.alias,
    # Safe operators (Note: ast.Pow is intentionally excluded to prevent exponentiation bombs)
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.BitAnd,
    ast.BitOr,
    ast.BitXor,
    ast.Invert,
    ast.UAdd,
    ast.USub,
    ast.Not,
    ast.And,
    ast.Or,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.Is,
    ast.IsNot,
    ast.In,
    ast.NotIn,
)

_ALLOWED_NODE_TYPES: tuple[type[ast.AST], ...] = (
    *_ALLOWED_STATEMENT_NODES,
    *_ALLOWED_EXPRESSION_AND_SUPPORT_NODES,
)

_FORBIDDEN_STRING_LITERAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:[A-Za-z]:\\|/(?:etc|proc|sys|var|home|root|work|tmp|dev|run)/)", re.IGNORECASE),
    re.compile(r"\b(?:https?|ftp|file|ws|wss)://", re.IGNORECASE),
    re.compile(r"(?:docker\.sock|__builtins__|__subclasses__|__globals__|__import__|__code__)", re.IGNORECASE),
    re.compile(r"\b(?:ignore\s+previous\s+instructions|system\s+prompt|developer\s+message)\b", re.IGNORECASE),
)


class ASTPolicyCode(StrEnum):
    SOURCE_BOUNDS_EXCEEDED = "SOURCE_BOUNDS_EXCEEDED"
    CONTROL_CHARACTER_REJECTED = "CONTROL_CHARACTER_REJECTED"
    SYNTAX_ERROR = "SYNTAX_ERROR"
    AST_COMPLEXITY_EXCEEDED = "AST_COMPLEXITY_EXCEEDED"
    DISALLOWED_NODE_TYPE = "DISALLOWED_NODE_TYPE"
    DISALLOWED_IMPORT = "DISALLOWED_IMPORT"
    UNDECLARED_IMPORT = "UNDECLARED_IMPORT"
    DUNDER_OR_PRIVATE_ACCESS = "DUNDER_OR_PRIVATE_ACCESS"
    FORBIDDEN_CALL = "FORBIDDEN_CALL"
    FORBIDDEN_ATTRIBUTE = "FORBIDDEN_ATTRIBUTE"
    UNSAFE_CONSTANT = "UNSAFE_CONSTANT"
    MISSING_ENTRYPOINT = "MISSING_ENTRYPOINT"
    SOURCE_TAMPERED = "SOURCE_TAMPERED"


class ASTPolicyError(ValueError):
    """Sanitized static AST validation error; never embeds untrusted source snippets."""

    def __init__(self, code: ASTPolicyCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"AST policy validation failed ({code.value}): {detail}")


@dataclass(frozen=True, slots=True)
class ASTValidationReceipt:
    """Static defense-in-depth receipt. Never authorizes host or unverified execution."""

    valid: Literal[True]
    code_sha256: str
    plan_sha256: str
    schema_sha256: str
    declared_imports: tuple[str, ...]
    node_count: int
    max_depth: int
    execution_authorized: Literal[False] = False
    sandbox_isolation_required: Literal[True] = True
    security_notice: str = (
        "AST validation is static defense-in-depth only and never replaces "
        "verified Linux container isolation (SEC01-SEC10)."
    )


def _check_source_text(source: str) -> str:
    if type(source) is not str:
        raise ASTPolicyError(ASTPolicyCode.SOURCE_BOUNDS_EXCEEDED, "Source must be a string.")
    encoded = source.encode("utf-8", errors="strict")
    if not 10 <= len(encoded) <= MAX_CODE_BYTES:
        raise ASTPolicyError(ASTPolicyCode.SOURCE_BOUNDS_EXCEEDED, "Source byte length out of bounds.")
    lines = source.splitlines()
    if not 1 <= len(lines) <= MAX_CODE_LINES:
        raise ASTPolicyError(ASTPolicyCode.SOURCE_BOUNDS_EXCEEDED, "Source line count out of bounds.")
    for ch in source:
        if ch in {"\n", "\r", "\t"}:
            continue
        if unicodedata.category(ch) in {"Cc", "Cf", "Cs"}:
            raise ASTPolicyError(
                ASTPolicyCode.CONTROL_CHARACTER_REJECTED,
                "Source contains disallowed control or formatting characters.",
            )
    return hashlib.sha256(encoded).hexdigest()


def _check_identifier(identifier: str, *, context: str) -> None:
    if not identifier or identifier.startswith("_") or "__" in identifier:
        raise ASTPolicyError(
            ASTPolicyCode.DUNDER_OR_PRIVATE_ACCESS,
            f"Identifier in {context} uses leading underscore or dunder pattern.",
        )
    if identifier in {"builtins", "__builtins__", "globals", "locals", "vars", "open", "eval", "exec", "compile"}:
        raise ASTPolicyError(
            ASTPolicyCode.FORBIDDEN_CALL,
            f"Identifier in {context} references restricted runtime symbol.",
        )


def _measure_tree(root: ast.AST) -> tuple[int, int]:
    """Return (node_count, max_depth) using an explicit stack to prevent recursion overflow."""
    stack: list[tuple[ast.AST, int]] = [(root, 1)]
    node_count = 0
    max_depth = 0
    while stack:
        node, depth = stack.pop()
        node_count += 1
        if depth > max_depth:
            max_depth = depth
        if node_count > MAX_AST_NODES or max_depth > MAX_AST_DEPTH:
            raise ASTPolicyError(
                ASTPolicyCode.AST_COMPLEXITY_EXCEEDED,
                "AST node count or depth exceeds static safety bounds.",
            )
        for child in ast.iter_child_nodes(node):
            stack.append((child, depth + 1))
    return node_count, max_depth


def validate_python_source_ast(
    python_source: str,
    *,
    declared_imports: tuple[str, ...],
    plan_sha256: str,
    schema_sha256: str,
    expected_code_sha256: str | None = None,
) -> ASTValidationReceipt:
    """Validate candidate Python source against strict static AST admission rules."""
    actual_sha256 = _check_source_text(python_source)
    if expected_code_sha256 is not None and actual_sha256 != expected_code_sha256:
        raise ASTPolicyError(
            ASTPolicyCode.SOURCE_TAMPERED,
            "Candidate source SHA-256 does not match expected hash.",
        )

    if not set(declared_imports).issubset(ALLOWED_AST_MODULES) or not set(declared_imports).issubset(_ALLOWED_CODE_IMPORTS):
        raise ASTPolicyError(
            ASTPolicyCode.DISALLOWED_IMPORT,
            "Declared imports contain a module outside the static allowlist.",
        )

    try:
        tree = ast.parse(python_source, filename="<sheetsafe-candidate>", mode="exec")
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        raise ASTPolicyError(
            ASTPolicyCode.SYNTAX_ERROR,
            "Candidate source failed Python syntax parsing.",
        ) from None

    node_count, max_depth = _measure_tree(tree)

    observed_imports: list[str] = []
    has_run_analysis = False

    # Check top-level statements: only imports, constant bindings, and single run_analysis def are permitted
    for top_node in tree.body:
        if not isinstance(top_node, _ALLOWED_NODE_TYPES):
            raise ASTPolicyError(
                ASTPolicyCode.DISALLOWED_NODE_TYPE,
                f"AST node type '{type(top_node).__name__}' is forbidden by static policy.",
            )
        if isinstance(top_node, ast.Import):
            for alias in top_node.names:
                mod_name = alias.name
                if mod_name not in ALLOWED_AST_MODULES:
                    raise ASTPolicyError(
                        ASTPolicyCode.DISALLOWED_IMPORT,
                        "Import statement requests a disallowed module.",
                    )
                allowed_aliases = ALLOWED_IMPORT_ALIASES.get(mod_name, frozenset())
                if alias.asname not in allowed_aliases:
                    raise ASTPolicyError(
                        ASTPolicyCode.DISALLOWED_IMPORT,
                        "Import alias is not in the approved alias mapping.",
                    )
                observed_imports.append(mod_name)
        elif isinstance(top_node, ast.ImportFrom):
            if top_node.level != 0 or top_node.module is None:
                raise ASTPolicyError(
                    ASTPolicyCode.DISALLOWED_IMPORT,
                    "Relative or module-less from-import is forbidden.",
                )
            if top_node.module == "matplotlib" and len(top_node.names) == 1 and top_node.names[0].name == "pyplot":
                full_mod = "matplotlib.pyplot"
                if top_node.names[0].asname not in ALLOWED_IMPORT_ALIASES[full_mod]:
                    raise ASTPolicyError(
                        ASTPolicyCode.DISALLOWED_IMPORT,
                        "Unapproved alias for matplotlib.pyplot.",
                    )
                observed_imports.append(full_mod)
            else:
                raise ASTPolicyError(
                    ASTPolicyCode.DISALLOWED_IMPORT,
                    "From-import is not permitted for this module.",
                )
        elif isinstance(top_node, ast.Assign):
            if len(top_node.targets) != 1 or not isinstance(top_node.targets[0], ast.Name):
                raise ASTPolicyError(
                    ASTPolicyCode.DISALLOWED_NODE_TYPE,
                    "Top-level assignments must bind a single constant identifier.",
                )
            _check_identifier(top_node.targets[0].id, context="top-level constant")
            if not (
                isinstance(top_node.value, ast.Constant)
                or (
                    isinstance(top_node.value, ast.Tuple)
                    and all(isinstance(elt, ast.Constant) for elt in top_node.value.elts)
                )
            ):
                raise ASTPolicyError(
                    ASTPolicyCode.DISALLOWED_NODE_TYPE,
                    "Top-level assignments may only bind constant literals or constant tuples.",
                )
        elif isinstance(top_node, ast.FunctionDef):
            _check_identifier(top_node.name, context="function definition")
            if top_node.decorator_list:
                raise ASTPolicyError(
                    ASTPolicyCode.DISALLOWED_NODE_TYPE,
                    "Function decorators are not permitted in candidate code.",
                )
            if top_node.name != "run_analysis" or has_run_analysis:
                raise ASTPolicyError(
                    ASTPolicyCode.MISSING_ENTRYPOINT,
                    "Candidate script may only define a single top-level 'run_analysis(records)' function.",
                )
            if len(top_node.args.args) != 1 or top_node.args.args[0].arg != "records":
                raise ASTPolicyError(
                    ASTPolicyCode.MISSING_ENTRYPOINT,
                    "run_analysis must accept exactly one positional argument named 'records'.",
                )
            if (
                top_node.args.vararg is not None
                or top_node.args.kwarg is not None
                or top_node.args.kwonlyargs
                or top_node.args.defaults
                or top_node.args.posonlyargs
            ):
                raise ASTPolicyError(
                    ASTPolicyCode.MISSING_ENTRYPOINT,
                    "run_analysis must not declare varargs, kwargs, or default arguments.",
                )
            has_run_analysis = True
        else:
            raise ASTPolicyError(
                ASTPolicyCode.DISALLOWED_NODE_TYPE,
                "Executable statements are not permitted at module top-level outside run_analysis.",
            )

    if not has_run_analysis:
        raise ASTPolicyError(
            ASTPolicyCode.MISSING_ENTRYPOINT,
            "Candidate script must define 'def run_analysis(records):'.",
        )

    if set(observed_imports) != set(declared_imports):
        raise ASTPolicyError(
            ASTPolicyCode.UNDECLARED_IMPORT,
            "Observed AST imports do not match candidate declared_imports.",
        )

    # Walk all nodes for strict node-type, identifier, attribute, call, and constant checks
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODE_TYPES):
            raise ASTPolicyError(
                ASTPolicyCode.DISALLOWED_NODE_TYPE,
                f"AST node type '{type(node).__name__}' is forbidden by static policy.",
            )

        if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
            raise ASTPolicyError(
                ASTPolicyCode.DISALLOWED_IMPORT,
                "Nested imports inside functions or blocks are forbidden.",
            )

        if isinstance(node, ast.FunctionDef) and node not in tree.body:
            raise ASTPolicyError(
                ASTPolicyCode.DISALLOWED_NODE_TYPE,
                "Nested function definitions are forbidden.",
            )

        if isinstance(node, ast.Name):
            _check_identifier(node.id, context="variable reference")
            if node.id in FORBIDDEN_CALL_NAMES:
                raise ASTPolicyError(
                    ASTPolicyCode.FORBIDDEN_CALL,
                    "Reference to a forbidden builtin or introspection symbol.",
                )

        elif isinstance(node, ast.arg):
            _check_identifier(node.arg, context="function parameter")

        elif isinstance(node, ast.Attribute):
            _check_identifier(node.attr, context="attribute access")
            if node.attr in FORBIDDEN_ATTRIBUTE_NAMES or node.attr not in ALLOWED_ATTRIBUTE_NAMES:
                raise ASTPolicyError(
                    ASTPolicyCode.FORBIDDEN_ATTRIBUTE,
                    f"Attribute '{node.attr}' is not on the static allowlist.",
                )

        elif isinstance(node, ast.keyword):
            if node.arg is None:
                raise ASTPolicyError(
                    ASTPolicyCode.DISALLOWED_NODE_TYPE,
                    "Dictionary unpacking (**kwargs) in function calls is forbidden.",
                )
            _check_identifier(node.arg, context="keyword argument")

        elif isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mult):
                for operand in (node.left, node.right):
                    if isinstance(operand, (ast.List, ast.Tuple)) or (
                        isinstance(operand, ast.Constant) and isinstance(operand.value, str)
                    ):
                        raise ASTPolicyError(
                            ASTPolicyCode.DISALLOWED_NODE_TYPE,
                            "String or sequence repetition via '*' is forbidden.",
                        )

        elif isinstance(node, ast.Call):
            if any(isinstance(arg, ast.Starred) for arg in node.args):
                raise ASTPolicyError(
                    ASTPolicyCode.DISALLOWED_NODE_TYPE,
                    "Starred argument unpacking (*args) in function calls is forbidden.",
                )
            if isinstance(node.func, ast.Name):
                fn_name = node.func.id
                if fn_name in FORBIDDEN_CALL_NAMES or fn_name not in ALLOWED_BARE_CALLS:
                    raise ASTPolicyError(
                        ASTPolicyCode.FORBIDDEN_CALL,
                        f"Direct call to '{fn_name}' is not permitted.",
                    )
            elif isinstance(node.func, ast.Attribute):
                attr_name = node.func.attr
                if attr_name in FORBIDDEN_ATTRIBUTE_NAMES or attr_name not in ALLOWED_ATTRIBUTE_NAMES:
                    raise ASTPolicyError(
                        ASTPolicyCode.FORBIDDEN_ATTRIBUTE,
                        f"Method call '{attr_name}' is not permitted.",
                    )
            else:
                raise ASTPolicyError(
                    ASTPolicyCode.FORBIDDEN_CALL,
                    "Dynamic or indirect callable expressions are forbidden.",
                )

        elif isinstance(node, ast.Constant):
            val = node.value
            if isinstance(val, (bytes, bytearray, complex)):
                raise ASTPolicyError(
                    ASTPolicyCode.UNSAFE_CONSTANT,
                    "Bytes and complex literals are not permitted in candidate scripts.",
                )
            if type(val) is int and abs(val) > MAX_INT_LITERAL_ABS:
                raise ASTPolicyError(
                    ASTPolicyCode.UNSAFE_CONSTANT,
                    "Integer constant exceeds static magnitude limit.",
                )
            if isinstance(val, str):
                if len(val) > MAX_STRING_LITERAL_CHARS:
                    raise ASTPolicyError(
                        ASTPolicyCode.UNSAFE_CONSTANT,
                        "String literal exceeds maximum allowed length.",
                    )
                if val.startswith("_") or "__" in val:
                    raise ASTPolicyError(
                        ASTPolicyCode.DUNDER_OR_PRIVATE_ACCESS,
                        "String literal contains leading underscore or dunder pattern.",
                    )
                if any(p.search(val) is not None for p in _FORBIDDEN_STRING_LITERAL_PATTERNS):
                    raise ASTPolicyError(
                        ASTPolicyCode.UNSAFE_CONSTANT,
                        "String literal contains forbidden path, URI, or runtime token.",
                    )

    return ASTValidationReceipt(
        valid=True,
        code_sha256=actual_sha256,
        plan_sha256=plan_sha256,
        schema_sha256=schema_sha256,
        declared_imports=tuple(declared_imports),
        node_count=node_count,
        max_depth=max_depth,
    )


def validate_candidate_ast(
    candidate: GeneratedCodeCandidate,
    *,
    expected_code_sha256: str | None = None,
) -> ASTValidationReceipt:
    """Validate a GeneratedCodeCandidate contract with the static AST policy validator."""
    if type(candidate) is not GeneratedCodeCandidate:
        raise ASTPolicyError(
            ASTPolicyCode.SOURCE_BOUNDS_EXCEEDED,
            "Expected a validated GeneratedCodeCandidate instance.",
        )
    return validate_python_source_ast(
        candidate.python_source,
        declared_imports=candidate.declared_imports,
        plan_sha256=candidate.plan_sha256,
        schema_sha256=candidate.schema_sha256,
        expected_code_sha256=expected_code_sha256,
    )
