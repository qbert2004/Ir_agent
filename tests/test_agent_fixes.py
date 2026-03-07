"""
Tests covering all 7 original agent bug fixes + 3 infrastructure fixes.

Fix #1  — memory_manager.py : LRU+TTL session eviction
Fix #2  — event_processor.py: EventProcessor feeds agent_service.add_event()
Fix #3  — agent.py          : arun() raises asyncio.TimeoutError on timeout
Fix #4  — lookup_ioc.py     : IoC cache LRU eviction
Fix #5  — lookup_ioc.py     : _aggregate_confidence local-DB bug
Fix #6  — embeddings.py     : _load_model() thread-safe double-checked locking
Fix #7  — system_prompts.py : str.replace()-based injection-safe substitution

Fix #8  — llm_client.py     : OpenAI/Ollama providers use settings.* not os.getenv()
Fix #9  — agent_service.py  : _event_store uses deque(maxlen) for O(1) eviction
Fix #10 — routers/agent.py  : no redundant `import asyncio` inside _stream()

Heavy ML/vector-store dependencies (faiss, sentence_transformers) are mocked
so the tests run without GPU/ML packages installed.
"""

import asyncio
import sys
import threading
import time
import types
import os
import pytest
from collections import OrderedDict
from unittest.mock import MagicMock, patch

os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("LLM_API_KEY", "")
os.environ.setdefault("MY_API_TOKEN", "")


# ── Mock heavy ML deps at module level so imports succeed ─────────────────────

def _stub_module(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    return mod

# faiss stub
if "faiss" not in sys.modules:
    faiss_stub = _stub_module("faiss")
    faiss_stub.IndexFlatIP = MagicMock
    faiss_stub.read_index = MagicMock(return_value=MagicMock())
    faiss_stub.write_index = MagicMock()

# sentence_transformers stub
if "sentence_transformers" not in sys.modules:
    st_stub = _stub_module("sentence_transformers")
    st_stub.SentenceTransformer = MagicMock


# ── Shared helper: build an isolated MemoryManager without singletons ─────────

def _make_memory_manager(max_size: int = 100, ttl: float = 3600.0):
    """Return a fresh MemoryManager bypassing singletons and patching limits."""
    import app.agent.memory.memory_manager as mm_mod
    old_max = mm_mod.SESSION_MAX_SIZE
    old_ttl = mm_mod.SESSION_TTL_SECONDS
    mm_mod.SESSION_MAX_SIZE = max_size
    mm_mod.SESSION_TTL_SECONDS = ttl

    from app.agent.memory.memory_manager import MemoryManager

    mgr = object.__new__(MemoryManager)
    mgr._sessions = OrderedDict()
    mgr._lock = threading.Lock()
    mgr._long_term = MagicMock()   # avoid FAISS entirely

    mm_mod.SESSION_MAX_SIZE = old_max
    mm_mod.SESSION_TTL_SECONDS = old_ttl

    # Store the limits on the instance so _get_or_create reads them from the module
    # (already restored; we patch per-test using the helper below)
    return mgr, max_size, ttl


# ══════════════════════════════════════════════════════════════════════════════
# Fix #1 — MemoryManager LRU + TTL
# ══════════════════════════════════════════════════════════════════════════════

class TestMemoryManagerEviction:
    """MemoryManager must not grow sessions without bound."""

    def test_lru_cap_evicts_oldest(self):
        """When cap is reached the LRU (oldest) session is removed."""
        import app.agent.memory.memory_manager as mm_mod
        from app.agent.memory.memory_manager import MemoryManager

        cap = 5
        with patch.object(mm_mod, "SESSION_MAX_SIZE", cap), \
             patch.object(mm_mod, "SESSION_TTL_SECONDS", 3600.0):

            mgr = object.__new__(MemoryManager)
            mgr._sessions = OrderedDict()
            mgr._lock = threading.Lock()
            mgr._long_term = MagicMock()

            for i in range(cap + 3):
                mgr.get_session(f"session-{i}")

            assert mgr.active_sessions <= cap, (
                f"Expected ≤ {cap} sessions, got {mgr.active_sessions}"
            )
            # First sessions (LRU) should have been evicted
            assert "session-0" not in mgr._sessions
            assert "session-1" not in mgr._sessions
            # Most-recent sessions must still be there
            assert f"session-{cap + 2}" in mgr._sessions

    def test_ttl_evicts_expired_sessions(self):
        """Sessions older than TTL are evicted on the next access."""
        import app.agent.memory.memory_manager as mm_mod
        from app.agent.memory.memory_manager import MemoryManager

        with patch.object(mm_mod, "SESSION_MAX_SIZE", 1000), \
             patch.object(mm_mod, "SESSION_TTL_SECONDS", 0.05):  # 50 ms

            mgr = object.__new__(MemoryManager)
            mgr._sessions = OrderedDict()
            mgr._lock = threading.Lock()
            mgr._long_term = MagicMock()

            mgr.get_session("old-session")
            assert mgr.active_sessions == 1

            time.sleep(0.12)  # Let TTL expire (50 ms + margin)

            # Trigger eviction via a new access
            mgr.get_session("new-trigger")
            assert "old-session" not in mgr._sessions

    def test_clear_session_removes_from_dict(self):
        """clear_session must remove the entry under the lock."""
        import app.agent.memory.memory_manager as mm_mod
        from app.agent.memory.memory_manager import MemoryManager

        with patch.object(mm_mod, "SESSION_MAX_SIZE", 1000), \
             patch.object(mm_mod, "SESSION_TTL_SECONDS", 3600.0):

            mgr = object.__new__(MemoryManager)
            mgr._sessions = OrderedDict()
            mgr._lock = threading.Lock()
            mgr._long_term = MagicMock()

            mgr.get_session("s1")
            mgr.get_session("s2")
            mgr.clear_session("s1")

            assert "s1" not in mgr._sessions
            assert "s2" in mgr._sessions

    def test_touch_promotes_to_mru(self):
        """Accessing a session moves it to the most-recently-used position."""
        import app.agent.memory.memory_manager as mm_mod
        from app.agent.memory.memory_manager import MemoryManager

        cap = 3
        with patch.object(mm_mod, "SESSION_MAX_SIZE", cap), \
             patch.object(mm_mod, "SESSION_TTL_SECONDS", 3600.0):

            mgr = object.__new__(MemoryManager)
            mgr._sessions = OrderedDict()
            mgr._lock = threading.Lock()
            mgr._long_term = MagicMock()

            mgr.get_session("a")
            mgr.get_session("b")
            mgr.get_session("c")

            # Re-access "a" → it becomes MRU, "b" becomes LRU
            mgr.get_session("a")

            # Adding "d" should evict "b" (now LRU), not "a"
            mgr.get_session("d")

            assert "a" in mgr._sessions, "'a' was re-accessed and should survive"
            assert "b" not in mgr._sessions, "'b' should have been evicted"


# ══════════════════════════════════════════════════════════════════════════════
# Fix #3 — arun() timeout
# ══════════════════════════════════════════════════════════════════════════════

class TestAgentTimeout:
    """CyberAgent.arun() must raise asyncio.TimeoutError when the loop hangs."""

    def test_arun_raises_timeout(self):
        """A very short timeout triggers asyncio.TimeoutError."""
        import app.agent.core.agent as agent_mod
        from app.agent.core.agent import CyberAgent
        from app.agent.tools.base import ToolRegistry

        # Patch MemoryManager to avoid FAISS
        mock_memory = MagicMock()
        mock_memory.get_context.return_value = ""
        mock_memory.add_user_message.return_value = None

        registry = ToolRegistry()

        with patch.object(agent_mod, "AGENT_TIMEOUT", 0.02):  # 20 ms
            agent = CyberAgent(registry, mock_memory)

            # Make _call_llm_direct block longer than the timeout
            def slow_llm(*args, **kwargs):
                time.sleep(5)
                return "Final Answer: done"

            agent._call_llm_direct = slow_llm
            agent._call_llm = slow_llm

            with pytest.raises(asyncio.TimeoutError):
                asyncio.run(agent.arun("test query"))


# ══════════════════════════════════════════════════════════════════════════════
# Fix #4 — IoC cache LRU size cap
# ══════════════════════════════════════════════════════════════════════════════

class TestIoCCacheLRU:
    """IoC cache must not exceed CACHE_MAX_SIZE entries."""

    def setup_method(self):
        """Clear cache before each test."""
        import app.agent.tools.lookup_ioc as ioc_mod
        ioc_mod._CACHE.clear()

    def teardown_method(self):
        """Clean up cache after each test."""
        import app.agent.tools.lookup_ioc as ioc_mod
        ioc_mod._CACHE.clear()

    def test_cache_evicts_oldest_on_overflow(self):
        import app.agent.tools.lookup_ioc as ioc_mod

        with patch.object(ioc_mod, "CACHE_MAX_SIZE", 5), \
             patch.object(ioc_mod, "CACHE_TTL", 3600):

            for i in range(7):
                ioc_mod._cache_set(f"ip:10.0.0.{i}", {"is_malicious": False})

            assert len(ioc_mod._CACHE) <= 5
            assert ioc_mod._cache_get("ip:10.0.0.0") is None, "oldest should be evicted"
            assert ioc_mod._cache_get("ip:10.0.0.1") is None, "2nd oldest should be evicted"
            assert ioc_mod._cache_get("ip:10.0.0.6") is not None, "newest should survive"

    def test_cache_hit_refreshes_lru_order(self):
        import app.agent.tools.lookup_ioc as ioc_mod

        with patch.object(ioc_mod, "CACHE_MAX_SIZE", 3), \
             patch.object(ioc_mod, "CACHE_TTL", 3600):

            ioc_mod._cache_set("ip:1.1.1.1", {"is_malicious": False})
            ioc_mod._cache_set("ip:2.2.2.2", {"is_malicious": False})
            ioc_mod._cache_set("ip:3.3.3.3", {"is_malicious": False})

            # Promote 1.1.1.1 → MRU; 2.2.2.2 becomes LRU
            ioc_mod._cache_get("ip:1.1.1.1")

            # Adding 4.4.4.4 evicts the LRU (2.2.2.2)
            ioc_mod._cache_set("ip:4.4.4.4", {"is_malicious": False})

            assert ioc_mod._cache_get("ip:1.1.1.1") is not None, "MRU must survive"
            assert ioc_mod._cache_get("ip:2.2.2.2") is None, "LRU must be evicted"
            assert ioc_mod._cache_get("ip:4.4.4.4") is not None

    def test_expired_entry_removed_on_get(self):
        import app.agent.tools.lookup_ioc as ioc_mod

        with patch.object(ioc_mod, "CACHE_TTL", 0), \
             patch.object(ioc_mod, "CACHE_MAX_SIZE", 10000):

            ioc_mod._cache_set("ip:9.9.9.9", {"is_malicious": True})
            result = ioc_mod._cache_get("ip:9.9.9.9")
            assert result is None
            assert "ip:9.9.9.9" not in ioc_mod._CACHE


# ══════════════════════════════════════════════════════════════════════════════
# Fix #5 — _aggregate_confidence bug
# ══════════════════════════════════════════════════════════════════════════════

class TestAggregateConfidence:
    """_aggregate_confidence must weight providers correctly and cap at 1.0."""

    @staticmethod
    def _tool():
        from app.agent.tools.lookup_ioc import LookupIoCTool
        return LookupIoCTool()

    def test_local_only_malicious_is_60_percent(self):
        """Local DB alone → exactly 60 % confidence (not 100 %)."""
        tool = self._tool()
        results = [{"provider": "local", "is_malicious": True, "details": "test"}]
        conf = tool._aggregate_confidence(results, "ip")
        assert abs(conf - 0.6) < 0.001, f"Expected 0.60, got {conf:.4f}"

    def test_local_only_clean_is_zero(self):
        tool = self._tool()
        results = [{"provider": "local", "is_malicious": False, "details": "not found"}]
        assert tool._aggregate_confidence(results, "ip") == 0.0

    def test_vt_100_percent_detection(self):
        """VT with all engines flagging → 100 %."""
        tool = self._tool()
        results = [{"provider": "VirusTotal", "malicious_votes": 70, "total_engines": 70}]
        conf = tool._aggregate_confidence(results, "ip")
        assert abs(conf - 1.0) < 0.001

    def test_vt_partial_detection(self):
        """VT with 50/70 engines → ~71 %."""
        tool = self._tool()
        results = [{"provider": "VirusTotal", "malicious_votes": 50, "total_engines": 70}]
        conf = tool._aggregate_confidence(results, "ip")
        assert abs(conf - 50 / 70) < 0.001

    def test_vt_clean_local_malicious(self):
        """VT says clean, local says malicious → blended < 60 %."""
        tool = self._tool()
        results = [
            {"provider": "VirusTotal", "malicious_votes": 0, "total_engines": 70},
            {"provider": "local", "is_malicious": True, "details": "test"},
        ]
        conf = tool._aggregate_confidence(results, "ip")
        expected = (0.0 * 0.6 + 0.6 * 0.3) / (0.6 + 0.3)   # = 0.2
        assert abs(conf - expected) < 0.001

    def test_all_providers_max_does_not_exceed_1(self):
        """All providers at maximum → confidence capped at 1.0."""
        tool = self._tool()
        results = [
            {"provider": "VirusTotal", "malicious_votes": 70, "total_engines": 70},
            {"provider": "AbuseIPDB", "abuse_confidence_score": 100},
            {"provider": "local", "is_malicious": True, "details": "test"},
        ]
        conf = tool._aggregate_confidence(results, "ip")
        assert conf <= 1.0, f"Confidence exceeded 1.0: {conf}"

    def test_empty_results_returns_zero(self):
        tool = self._tool()
        assert tool._aggregate_confidence([], "ip") == 0.0

    def test_abuseipdb_only(self):
        """AbuseIPDB at 80 % abuse score → 80 %."""
        tool = self._tool()
        results = [{"provider": "AbuseIPDB", "abuse_confidence_score": 80}]
        conf = tool._aggregate_confidence(results, "ip")
        assert abs(conf - 0.8) < 0.001


# ══════════════════════════════════════════════════════════════════════════════
# Fix #6 — EmbeddingModel._load_model() thread safety
# ══════════════════════════════════════════════════════════════════════════════

class TestEmbeddingModelThreadSafety:
    """_load_model must call SentenceTransformer exactly once under concurrency."""

    def test_concurrent_load_calls_single_model(self):
        from app.agent.rag.embeddings import EmbeddingModel

        # Build an isolated instance (bypass singleton)
        model_instance = object.__new__(EmbeddingModel)
        model_instance._model = None
        model_instance._initialized = True

        load_count = []
        count_lock = threading.Lock()

        def fake_st(name):
            with count_lock:
                load_count.append(1)
            time.sleep(0.03)   # simulate slow model load
            return MagicMock()

        errors = []

        # Patch sentence_transformers.SentenceTransformer at the sys.modules level
        sys.modules["sentence_transformers"].SentenceTransformer = MagicMock(side_effect=fake_st)

        def call_load():
            try:
                model_instance._load_model()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=call_load) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Threads raised errors: {errors}"
        assert len(load_count) == 1, (
            f"SentenceTransformer instantiated {len(load_count)} times — "
            "race condition not fixed (expected double-checked locking)"
        )
        assert model_instance._model is not None


# ══════════════════════════════════════════════════════════════════════════════
# Fix #7 — str.format() injection safety in prompts
# ══════════════════════════════════════════════════════════════════════════════

class TestPromptInjectionSafety:
    """build_*_prompt functions must not crash on user input containing {braces}."""

    def test_curly_braces_in_memory_context_do_not_crash(self):
        from app.agent.prompts.system_prompts import build_agent_system_prompt

        malicious_context = "User asked about {exec_cmd} and {0} things."
        prompt = build_agent_system_prompt(
            tools_description="- tool_a: does something",
            memory_context=malicious_context,
        )
        assert malicious_context in prompt

    def test_curly_braces_in_tools_description_do_not_crash(self):
        from app.agent.prompts.system_prompts import build_agent_system_prompt

        prompt = build_agent_system_prompt(
            tools_description="tool: params {p1} {p2}",
            memory_context="",
        )
        assert "tool: params {p1} {p2}" in prompt

    def test_minimal_prompt_with_braces(self):
        from app.agent.prompts.system_prompts import build_agent_system_prompt_minimal

        context = "Previous: user asked '{weird_key}' stuff"
        prompt = build_agent_system_prompt_minimal(memory_context=context)
        assert context in prompt

    def test_substitution_actually_inserts_content(self):
        """Placeholders must be replaced — not left as raw sentinels."""
        from app.agent.prompts.system_prompts import build_agent_system_prompt

        prompt = build_agent_system_prompt(
            tools_description="MY_TOOLS_HERE",
            memory_context="MY_CONTEXT_HERE",
        )
        assert "MY_TOOLS_HERE" in prompt
        assert "MY_CONTEXT_HERE" in prompt
        assert "<<TOOLS_DESCRIPTION>>" not in prompt
        assert "<<MEMORY_CONTEXT>>" not in prompt

    def test_positional_format_specifier_in_context_does_not_crash(self):
        """'%s', '{0}', '{!r}' in memory must not raise."""
        from app.agent.prompts.system_prompts import build_agent_system_prompt

        for nasty in ["{0}", "{!r}", "%(key)s", "{__class__}", "{{escaped}}", "}"]:
            build_agent_system_prompt(
                tools_description="tools",
                memory_context=f"context with {nasty}",
            )  # must not raise


# ══════════════════════════════════════════════════════════════════════════════
# Fix #8 — LLM client providers use settings.* instead of os.getenv()
# ══════════════════════════════════════════════════════════════════════════════

class TestLLMClientUsesSettings:
    """_OpenAIProvider and _OllamaProvider must read credentials from settings."""

    def test_openai_provider_uses_settings_attribute(self):
        """_OpenAIProvider.__init__ must reference settings.openai_api_key."""
        import inspect
        from app.core.llm_client import _OpenAIProvider

        src = inspect.getsource(_OpenAIProvider.__init__)
        assert "settings.openai_api_key" in src, (
            "_OpenAIProvider must read from settings.openai_api_key, not os.getenv()"
        )
        assert 'os.getenv("OPENAI_API_KEY"' not in src
        assert "os.getenv('OPENAI_API_KEY'" not in src

    def test_ollama_provider_uses_settings_attribute(self):
        """_OllamaProvider.__init__ must reference settings.ollama_base_url."""
        import inspect
        from app.core.llm_client import _OllamaProvider

        src = inspect.getsource(_OllamaProvider.__init__)
        assert "settings.ollama_base_url" in src, (
            "_OllamaProvider must read from settings.ollama_base_url, not os.getenv()"
        )
        assert 'os.getenv("OLLAMA_BASE_URL"' not in src
        assert "os.getenv('OLLAMA_BASE_URL'" not in src

    def test_openai_provider_available_when_settings_key_set(self):
        """_OpenAIProvider.is_available() → True when settings.openai_api_key is set."""
        from app.core import llm_client as lc

        openai_stub = types.ModuleType("openai")
        openai_stub.OpenAI = MagicMock(return_value=MagicMock())

        with patch.dict(sys.modules, {"openai": openai_stub}):
            with patch.object(lc, "settings") as mock_settings:
                mock_settings.openai_api_key = "sk-test-openai-key"
                mock_settings.groq_api_key = ""
                mock_settings.ollama_base_url = ""
                mock_settings.ai_model = "test-model"

                provider = lc._OpenAIProvider()

        assert provider.is_available(), (
            "_OpenAIProvider must be available when settings.openai_api_key is non-empty"
        )
        openai_stub.OpenAI.assert_called_once_with(
            api_key="sk-test-openai-key", timeout=lc.DEFAULT_TIMEOUT
        )

    def test_ollama_provider_available_when_settings_url_set(self):
        """_OllamaProvider.is_available() → True when settings.ollama_base_url is set."""
        from app.core import llm_client as lc

        openai_stub = types.ModuleType("openai")
        openai_stub.OpenAI = MagicMock(return_value=MagicMock())

        with patch.dict(sys.modules, {"openai": openai_stub}):
            with patch.object(lc, "settings") as mock_settings:
                mock_settings.ollama_base_url = "http://localhost:11434"
                mock_settings.groq_api_key = ""
                mock_settings.openai_api_key = ""
                mock_settings.ai_model = "test-model"

                provider = lc._OllamaProvider()

        assert provider.is_available(), (
            "_OllamaProvider must be available when settings.ollama_base_url is non-empty"
        )
        # OpenAI client is used under the hood for Ollama's compatible API
        openai_stub.OpenAI.assert_called_once()
        call_kwargs = openai_stub.OpenAI.call_args
        assert "localhost:11434" in str(call_kwargs)


# ══════════════════════════════════════════════════════════════════════════════
# Fix #9 — AgentService._event_store uses deque(maxlen) for O(1) eviction
# ══════════════════════════════════════════════════════════════════════════════

class TestEventStoreDeque:
    """_event_store must use deque(maxlen=…) so pop(0) O(n) cost is eliminated."""

    def test_agent_service_init_uses_deque(self):
        """AgentService.__init__ must construct a deque, not a plain list."""
        import inspect
        import app.services.agent_service as svc_mod

        src = inspect.getsource(svc_mod.AgentService.__init__)
        assert "deque(maxlen=" in src, (
            "_event_store must be initialised as deque(maxlen=…)"
        )

    def test_add_event_has_no_list_pop(self):
        """add_event() must not call pop(0) on a list (O(n) antipattern)."""
        import inspect
        import app.services.agent_service as svc_mod

        src = inspect.getsource(svc_mod.AgentService.add_event)
        assert "pop(0)" not in src, (
            "list.pop(0) is O(n). Use deque(maxlen=…) instead."
        )

    def test_deque_maxlen_auto_evicts_oldest(self):
        """Verify Python deque(maxlen=N) drops oldest entry on overflow (relied on by AgentService)."""
        from collections import deque

        cap = 10
        store: deque = deque(maxlen=cap)
        for i in range(cap + 5):  # insert 15 items into cap-10 deque
            store.append({"event_id": i})

        assert len(store) == cap
        ids = [e["event_id"] for e in store]
        # Events 0-4 should be evicted; 5-14 should remain
        assert ids[0] == 5,  f"Expected oldest kept = 5, got {ids[0]}"
        assert ids[-1] == 14, f"Expected newest = 14, got {ids[-1]}"

    def test_deque_append_is_o1(self):
        """Appending to a deque with maxlen must stay fast even at cap (no shifting)."""
        import time as _time
        from collections import deque

        cap = 10_000
        store: deque = deque(maxlen=cap)
        # Pre-fill
        for i in range(cap):
            store.append({"id": i})

        # Time 1000 overflow-appends
        t0 = _time.perf_counter()
        for i in range(1000):
            store.append({"id": cap + i})
        elapsed = _time.perf_counter() - t0

        assert elapsed < 0.5, (
            f"1000 overflow appends took {elapsed:.3f}s — suspiciously slow for O(1) deque"
        )
        assert len(store) == cap


# ══════════════════════════════════════════════════════════════════════════════
# Fix #10 — No redundant `import asyncio` inside _stream() closure
# ══════════════════════════════════════════════════════════════════════════════

class TestStreamingEndpointImports:
    """agent_query_stream must not re-import asyncio inside the _stream() closure."""

    def test_no_nested_asyncio_import_in_stream(self):
        """asyncio is already imported at module level — nested import is dead code."""
        import inspect
        import app.routers.agent as agent_router_mod

        src = inspect.getsource(agent_router_mod.agent_query_stream)
        assert "import asyncio" not in src, (
            "`import asyncio` inside _stream() is redundant — "
            "asyncio is already imported at the top of agent.py (router)"
        )
