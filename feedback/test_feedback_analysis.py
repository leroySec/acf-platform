
import os
import sys
import importlib
import inspect
import ast
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ======================================================================
# Class 1 — Package and module exist
# ======================================================================

class TestPackageExists:

    def test_feedback_package_importable(self):
        import feedback
        assert feedback is not None

    def test_feedback_analysis_module_importable(self):
        module = importlib.import_module("feedback.feedback_analysis")
        assert module is not None

    def test_module_source_file_exists(self):
        module = importlib.import_module("feedback.feedback_analysis")
        assert os.path.isfile(module.__file__)

    def test_module_has_no_syntax_errors(self):
        module = importlib.import_module("feedback.feedback_analysis")
        path = module.__file__
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        ast.parse(source)  # raises if invalid


# ======================================================================
# Class 2 — Required Config constants
# ======================================================================

class TestConfigConstants:

    def test_eval_cycles(self):
        from config import Config
        assert hasattr(Config, "FEEDBACK_EVAL_CYCLES")
        assert isinstance(Config.FEEDBACK_EVAL_CYCLES, int)
        assert Config.FEEDBACK_EVAL_CYCLES > 0

    def test_history_max(self):
        from config import Config
        assert hasattr(Config, "FEEDBACK_HISTORY_MAX")
        assert isinstance(Config.FEEDBACK_HISTORY_MAX, int)
        assert Config.FEEDBACK_HISTORY_MAX > 0

    def test_aggregates_file(self):
        from config import Config
        assert hasattr(Config, "FEEDBACK_AGGREGATES_FILE")
        assert isinstance(Config.FEEDBACK_AGGREGATES_FILE, str)
        assert Config.FEEDBACK_AGGREGATES_FILE

    def test_sensitivity_bounds(self):
        from config import Config
        assert Config.FEEDBACK_AUTO_SENSITIVITY_MIN < \
               Config.FEEDBACK_AUTO_SENSITIVITY_MAX
        assert Config.FEEDBACK_AUTO_SENSITIVITY_DELTA > 0

    def test_detector_weight_bounds(self):
        from config import Config
        assert Config.FEEDBACK_AUTO_DETECTOR_WEIGHT_MIN < \
               Config.FEEDBACK_AUTO_DETECTOR_WEIGHT_MAX
        assert Config.FEEDBACK_AUTO_DETECTOR_WEIGHT_DELTA > 0

    def test_fp_constants(self):
        from config import Config
        assert Config.FEEDBACK_FP_WINDOW_CYCLES > 0
        assert 0 <= Config.FEEDBACK_FP_CONFIDENCE_FLOOR <= 100
        assert Config.FEEDBACK_FP_REPEAT_THRESHOLD > 0

    def test_recommendation_bounds(self):
        from config import Config
        assert Config.FEEDBACK_RECOMMEND_THRESHOLD_MIN_DELTA < 0
        assert Config.FEEDBACK_RECOMMEND_THRESHOLD_MAX_DELTA > 0

    def test_section_names(self):
        from config import Config
        assert Config.FEEDBACK_SECTION_PREFIX == "layer_5_feedback"
        assert Config.FEEDBACK_GLOBAL_SECTION == "layer_5_feedback"


# ======================================================================
# Class 3 — Module purity (the contract)
# ======================================================================

class TestModulePurity:
    """
    feedback_analysis is pure: dicts in, dicts out. No Blackboard. No
    I/O. No subprocess. No network. No emit.
    """

    FORBIDDEN_IMPORTS = {
        "subprocess", "socket", "requests", "urllib",
        "http", "ftplib", "telnetlib",
    }

    FORBIDDEN_PROJECT_IMPORTS = {
        "event_emit", "event_router", "event_reader",
        "platform_utils",       # file locks, temp paths
    }

    def _imported_names(self):
        module = importlib.import_module("feedback.feedback_analysis")
        path = module.__file__
        with open(path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names.add(node.module.split(".")[0])
        return names

    def test_no_forbidden_stdlib_imports(self):
        imports = self._imported_names()
        overlaps = imports & self.FORBIDDEN_IMPORTS
        assert overlaps == set(), f"forbidden imports: {overlaps}"

    def test_no_forbidden_project_imports(self):
        imports = self._imported_names()
        overlaps = imports & self.FORBIDDEN_PROJECT_IMPORTS
        assert overlaps == set(), f"forbidden imports: {overlaps}"

    def test_no_top_level_file_writes(self):
        """No open(..., 'w') at import time."""
        module = importlib.import_module("feedback.feedback_analysis")
        path = module.__file__
        with open(path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                func = getattr(call, "func", None)
                if isinstance(func, ast.Name) and func.id == "open":
                    pytest.fail("top-level open() call found")


# ======================================================================
# Class 4 — Required function signatures
# ======================================================================

class TestFunctionSignatures:

    REQUIRED_FUNCTIONS = [
        "compute_risk_reduction",
        "compute_false_positive",
        "compute_resource_cost",
        "compute_response_time",
        "build_recommendation",
        "update_detector_weights",
        "update_memory",
        "append_history",
        "rollup_aggregates",
        "aggregate_global",
    ]

    @pytest.mark.parametrize("name", REQUIRED_FUNCTIONS)
    def test_function_exists(self, name):
        module = importlib.import_module("feedback.feedback_analysis")
        assert hasattr(module, name), f"missing: {name}"

    @pytest.mark.parametrize("name", REQUIRED_FUNCTIONS)
    def test_function_is_callable(self, name):
        module = importlib.import_module("feedback.feedback_analysis")
        fn = getattr(module, name)
        assert callable(fn)

    @pytest.mark.parametrize("name", REQUIRED_FUNCTIONS)
    def test_function_has_docstring(self, name):
        module = importlib.import_module("feedback.feedback_analysis")
        fn = getattr(module, name)
        assert fn.__doc__ and fn.__doc__.strip(), \
            f"{name} has no docstring"

    @pytest.mark.parametrize("name", REQUIRED_FUNCTIONS)
    def test_function_parameter_count_is_sane(self, name):
        module = importlib.import_module("feedback.feedback_analysis")
        fn = getattr(module, name)
        sig = inspect.signature(fn)
        assert len(sig.parameters) <= 6, \
            f"{name} has too many parameters"


# ======================================================================
# Class 5 — Determinism and immutability
# ======================================================================

class TestDeterminism:

    def test_compute_risk_reduction_is_deterministic(self):
        from feedback import feedback_analysis as fa
        import time
        now = time.time()
        args = {
            "ais_now": {"risk": 40, "ais_timestamp": now},
            "response_section": {"actions": []},
            "now": now,
        }
        a = fa.compute_risk_reduction(**args)
        b = fa.compute_risk_reduction(**args)
        assert a == b

    def test_no_mutation_of_input_dicts(self):
        from feedback import feedback_analysis as fa
        import time
        now = time.time()
        ais = {"risk": 40, "ais_timestamp": now}
        resp = {"actions": [{"ts": now - 400, "risk_at_action": 80}]}
        ais_snapshot = dict(ais)
        resp_snapshot = {"actions": [dict(resp["actions"][0])]}

        fa.compute_risk_reduction(
            ais_now=ais, response_section=resp, now=now)

        assert ais == ais_snapshot
        assert resp == resp_snapshot


# ======================================================================
# Class 6 — Safe defaults on empty input
# ======================================================================

class TestSafeOnEmptyInput:

    @pytest.mark.parametrize("fn_name,kwargs", [
        ("compute_risk_reduction",
         {"ais_now": {}, "response_section": {}, "now": 0.0}),
        ("compute_false_positive",
         {"response_section": {}, "whitelist_ips": [],
          "state_history": [], "now": 0.0}),
        ("compute_resource_cost",
         {"monitor_section": {}, "response_section": {}, "now": 0.0}),
        ("compute_response_time",
         {"state_section": {}, "response_section": {}}),
        ("build_recommendation",
         {"fp_rate": 0.0, "risk_reduction_avg": 0.0, "action_count": 0}),
        ("update_detector_weights",
         {"detector_stats": {}, "action_outcomes": {},
          "current_weights": {}}),
        ("update_memory",
         {"existing_memory": {}, "actions": [], "judgment": {}}),
        ("append_history",
         {"history": [], "entry": {}}),
        ("rollup_aggregates", {"history": []}),
        ("aggregate_global", {"per_capability": {}}),
    ])
    def test_function_returns_dict_on_empty_input(self, fn_name, kwargs):
        from feedback import feedback_analysis as fa
        fn = getattr(fa, fn_name)
        result = fn(**kwargs)
        assert isinstance(result, dict), \
            f"{fn_name} returned {type(result).__name__}, not dict"

    @pytest.mark.parametrize("fn_name,kwargs", [
        ("compute_risk_reduction",
         {"ais_now": None, "response_section": None, "now": 0.0}),
        ("compute_false_positive",
         {"response_section": None, "whitelist_ips": None,
          "state_history": None, "now": 0.0}),
        ("compute_resource_cost",
         {"monitor_section": None, "response_section": None, "now": 0.0}),
    ])
    def test_function_safe_on_none_input(self, fn_name, kwargs):
        from feedback import feedback_analysis as fa
        fn = getattr(fa, fn_name)
        try:
            result = fn(**kwargs)
        except Exception as e:
            pytest.fail(f"{fn_name} raised on None input: {e}")
        assert isinstance(result, dict)