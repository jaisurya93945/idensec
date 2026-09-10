"""Load AgentDojo's task data without its model-provider dependencies.

We need the published task definitions and tool schemas, not the agent
pipeline. A meta-path finder fabricates the provider SDKs on demand, which
keeps a large dependency tree out of the way and makes it structurally obvious
that no model is involved anywhere in this evaluation.
"""

import importlib.abc
import importlib.machinery
import sys
import types

STUB_ROOTS = (
    "anthropic", "openai", "cohere", "google", "langchain", "langchain_core",
    "tenacity", "dotenv", "rich", "click",
)


class _Anything:
    """Stands in for any class, decorator or factory a provider SDK exports.

    Accepts any construction, any call, any attribute and any subscript, so
    that module-level code such as ``@retry(wait=wait_random_exponential(...))``
    executes without the real library present.
    """

    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        if len(args) == 1 and not kwargs and callable(args[0]):
            return args[0]  # used as a bare decorator
        return _Anything()

    def __getattr__(self, item):
        if item.startswith("__"):
            raise AttributeError(item)
        return _Anything()

    def __getitem__(self, item):
        return _Anything()

    def __or__(self, other):
        return _Anything()

    __ror__ = __or__


class _AnyMeta(type):
    """Attribute access on the *class* must work too.

    Provider SDKs are frequently imported as namespaces and used as
    ``genai_types.Schema``, which reaches the metaclass rather than an instance.
    """

    def __getattr__(cls, item):
        if item.startswith("__"):
            raise AttributeError(item)
        made = _make(item)
        setattr(cls, item, made)
        return made

    def __call__(cls, *args, **kwargs):
        if len(args) == 1 and not kwargs and callable(args[0]):
            return args[0]  # used as a bare decorator
        return super().__call__(*args, **kwargs)

    def __or__(cls, other):
        return cls

    __ror__ = __or__

    def __getitem__(cls, item):
        return cls


def _make(name):
    """A callable class object usable as a base class, decorator or factory."""
    return _AnyMeta(name, (_Anything,), {})


class _AnyAttr(types.ModuleType):
    """A module where every attribute exists and tolerates any use."""

    def __getattr__(self, item):
        if item.startswith("__"):
            raise AttributeError(item)
        made = _make(item)
        setattr(self, item, made)
        return made


class _StubFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".")[0]
        if root not in STUB_ROOTS:
            return None
        return importlib.machinery.ModuleSpec(fullname, self, is_package=True)

    def create_module(self, spec):
        module = _AnyAttr(spec.name)
        module.__path__ = []  # a package, so submodules resolve through us too
        return module

    def exec_module(self, module):
        if module.__name__ == "tenacity":
            module.retry = lambda *a, **k: (lambda f: f)
            module.wait_random_exponential = lambda *a, **k: None
            module.stop_after_attempt = lambda *a, **k: None
            module.retry_if_not_exception_type = lambda *a, **k: None
        if module.__name__ == "dotenv":
            module.load_dotenv = lambda *a, **k: None


def install_stubs():
    if not any(isinstance(f, _StubFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, _StubFinder())


def suites(version: str = "v1"):
    """Load the published suites through AgentDojo's own registry.

    Importing a suite module directly triggers a circular import, because the
    package registers later task versions against the v1 modules on import.
    Going through the registry is both the supported path and the one that
    yields exactly the task set the benchmark defines.
    """
    install_stubs()
    from agentdojo.task_suite.load_suites import get_suites

    return dict(get_suites(version))
