# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Inert host facts only; never create PSEC, launch workloads or change accounts."""

import ctypes as c
import json
import os
import sys
import unittest

MXC = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
API_SET = b"api-win-appmodel-processmodel~securityenvironment"
EXPORTS = (
    b"CreateProcessSecurityEnvironment",
    b"QueryProcessSecurityEnvironmentSupport",
    b"IsProcessSecurityEnvironmentVersionSupported",
    b"CloseProcessSecurityEnvironment",
)
P, U8, U16, U32, U64, I32 = c.c_void_p, c.c_uint8, c.c_uint16, c.c_uint32, c.c_uint64, c.c_int32
SYSTEM32 = 0x800


class Version(c.Structure):
    _fields_ = [
        ("size", U32),
        ("major", U32),
        ("minor", U32),
        ("build", U32),
        ("platform", U32),
        ("service_pack", U16 * 128),
        ("sp_major", U16),
        ("sp_minor", U16),
        ("suite", U16),
        ("product", U8),
        ("reserved", U8),
    ]


def require(value):
    if not value:
        raise ValueError("fixed_refusal")


def number(value, maximum):
    require(type(value) is int and 0 <= value <= maximum)
    return value


def scope():
    return {
        "schema": 1,
        "diagnostic_only": True,
        "authorization_granted": False,
        "production_qualification": False,
        "psec_created": False,
        "workload_launched": False,
        "accounts_or_policies_changed": False,
        "completed": False,
    }


def observe(api):
    result, stage = scope(), "binding"
    try:
        api.open()
        stage = "os_version"
        version = api.os_version()
        require(type(version) is tuple and len(version) == 4)
        for value in version:
            number(value, 0xFFFFFFFF)
        require(version[2] > 0 and version[3] in (1, 2, 3))
        result.update(zip(("os_major", "os_minor", "os_build", "os_product_type"), version))
        stage = "token_elevation"
        result["token_is_elevated"] = bool(number(api.elevation(), 1))
        stage = "api_set"
        present = api.api_set()
        require(present is None or type(present) is bool)
        result.update(
            api_set_query_available=present is not None,
            psec_api_set_implemented=present,
            processmodel_load_attempted=False,
            processmodel_loaded=None,
            export_create=None,
            export_query_support=None,
            export_version=None,
            export_close=None,
            required_exports_complete=False,
            version_query_attempted=False,
            version_hresult=None,
            major1_available=None,
            supported_minor=None,
            support_query_attempted=False,
            support_hresult=None,
            support_flags=None,
        )
        if present is True:
            stage = "system32_processmodel"
            result["processmodel_load_attempted"] = True
            loaded = api.processmodel()
            require(type(loaded) is bool)
            result["processmodel_loaded"] = loaded
            if loaded:
                stage = "export_resolution"
                exports = api.exports()
                require(type(exports) is tuple and len(exports) == 4 and all(type(v) is bool for v in exports))
                result.update(zip(("export_create", "export_query_support", "export_version", "export_close"), exports))
                result["required_exports_complete"] = exports[0] and exports[1] and exports[3]
                if result["required_exports_complete"]:
                    if exports[2]:
                        stage = "version_query"
                        result["version_query_attempted"] = True
                        hr, available, minor = api.version()
                        require(type(hr) is int and -(1 << 31) <= hr < (1 << 31))
                        result["version_hresult"] = hr & 0xFFFFFFFF
                        if hr >= 0:
                            result["major1_available"] = number(available, 255) != 0
                            result["supported_minor"] = number(minor, 0xFFFFFFFF) if available else None
                    stage = "support_query"
                    result["support_query_attempted"] = True
                    hr, flags = api.support()
                    require(type(hr) is int and -(1 << 31) <= hr < (1 << 31))
                    result["support_hresult"] = hr & 0xFFFFFFFF
                    if hr >= 0:
                        result["support_flags"] = number(flags, (1 << 64) - 1)
        result["completed"] = True
    except Exception:
        result = {**scope(), "refusal_stage": stage}
    finally:
        try:
            closed = api.close()
        except Exception:
            closed = False
        if closed is not True:
            result = {**scope(), "refusal_stage": "resource_cleanup"}
        result["all_owned_resources_closed"] = closed is True
    return result


class Native:
    def __init__(self):
        self.modules, self.tokens, self.addresses = [], [], ()
        self.kernel = self.free = self.close_handle = None

    def open(self):
        require(sys.platform == "win32" and c.sizeof(P) == 8 and c.sizeof(Version) == 284)
        self.kernel = c.WinDLL("kernel32.dll", winmode=SYSTEM32, use_last_error=True)
        self.modules.append(self.kernel._handle)
        self.free = self.kernel.FreeLibrary
        self.free.argtypes, self.free.restype = [P], I32
        self.close_handle = self.kernel.CloseHandle
        self.close_handle.argtypes, self.close_handle.restype = [P], I32
        self.load = self.kernel.LoadLibraryExW
        self.load.argtypes, self.load.restype = [c.c_wchar_p, P, U32], P
        self.get = self.kernel.GetProcAddress
        self.get.argtypes, self.get.restype = [P, c.c_char_p], P

    def module(self, name):
        require(name in ("ntdll.dll", "advapi32.dll", "api-ms-win-core-apiquery-l2-1-0.dll", "processmodel.dll"))
        value = self.load(name, None, SYSTEM32)
        if value:
            self.modules.append(value)
        return value

    def function(self, module, name, result, arguments):
        address = self.get(module, name)
        require(address)
        return c.WINFUNCTYPE(result, *arguments, use_last_error=True)(address)

    def os_version(self):
        module = self.module("ntdll.dll")
        require(module)
        fn = self.function(module, b"RtlGetVersion", I32, [c.POINTER(Version)])
        value = Version()
        value.size = c.sizeof(value)
        require(fn(c.byref(value)) == 0)
        return value.major, value.minor, value.build, value.product

    def elevation(self):
        module = self.module("advapi32.dll")
        require(module)
        current = self.function(self.kernel._handle, b"GetCurrentProcess", P, [])()
        opening = self.function(module, b"OpenProcessToken", I32, [P, U32, c.POINTER(P)])
        token = P()
        ok = opening(current, 8, c.byref(token))  # TOKEN_QUERY only.
        if token.value and token.value != P(-1).value:
            self.tokens.append(token.value)
        require(ok and token.value and token.value != P(-1).value)
        query = self.function(module, b"GetTokenInformation", I32, [P, U32, P, U32, c.POINTER(U32)])
        value, used = U32(), U32()
        require(query(token, 20, c.byref(value), 4, c.byref(used)) and used.value == 4)
        return value.value

    def api_set(self):
        module = self.module("api-ms-win-core-apiquery-l2-1-0.dll")
        if not module:
            return None
        address = self.get(module, b"IsApiSetImplemented")
        if not address:
            return None
        return bool(c.WINFUNCTYPE(I32, c.c_char_p, use_last_error=True)(address)(API_SET))

    def processmodel(self):
        self.model = self.module("processmodel.dll")
        return bool(self.model)

    def exports(self):
        self.addresses = tuple(self.get(self.model, name) for name in EXPORTS)
        return tuple(bool(value) for value in self.addresses)

    def version(self):
        # Pinned MXC secenv.rs: HRESULT(DWORD, BOOLEAN*, DWORD*); BOOLEAN is ONE byte.
        fn = c.WINFUNCTYPE(I32, U32, c.POINTER(U8), c.POINTER(U32))(self.addresses[2])
        available, minor = U8(), U32()
        hr = fn(1, c.byref(available), c.byref(minor))
        return hr, available.value, minor.value

    def support(self):
        fn = c.WINFUNCTYPE(I32, c.POINTER(U64))(self.addresses[1])
        flags = U64()
        return fn(c.byref(flags)), flags.value

    def close(self):
        clean = True
        for values, close in ((self.tokens, self.close_handle), (self.modules, self.free)):
            while values:
                value = values.pop()
                try:
                    clean = bool(close and close(value)) and clean
                except Exception:
                    clean = False
        return clean


class Fake:
    def __init__(self):
        self.present, self.loaded, self.clean, self.elevated = True, True, True, 1
        self.found, self.version_value, self.support_value = (True, True, True, True), (0, 1, 1), (0, 13)
        self.trace = []

    def open(self):
        self.trace.append("open")

    def os_version(self):
        return 10, 0, 26100, 3

    def elevation(self):
        return self.elevated

    def api_set(self):
        return self.present

    def processmodel(self):
        self.trace.append("load")
        return self.loaded

    def exports(self):
        self.trace.append("exports")
        return self.found

    def version(self):
        self.trace.append("version")
        return self.version_value

    def support(self):
        self.trace.append("support")
        return self.support_value

    def close(self):
        self.trace.append("close")
        return self.clean


class Tests(unittest.TestCase):
    def test_elevation_is_observed_without_authorizing(self):
        self.assertEqual(c.sizeof(Version), 284)
        self.assertEqual(Version.product.offset, 282)
        self.assertEqual(c.sizeof(U8), 1)
        for value in (0, 1):
            api = Fake()
            api.elevated = value
            result = observe(api)
            self.assertTrue(result["completed"])
            self.assertEqual(result["token_is_elevated"], bool(value))
            self.assertFalse(result["authorization_granted"])
            self.assertFalse(result["psec_created"])
            self.assertFalse(result["workload_launched"])

    def test_unavailable_or_unknown_api_set_never_loads_processmodel(self):
        for value in (None, False):
            api = Fake()
            api.present = value
            result = observe(api)
            self.assertTrue(result["completed"])
            self.assertIs(result["psec_api_set_implemented"], value)
            self.assertNotIn("load", api.trace)
            self.assertIsNone(result["export_create"])
        api = Fake()
        api.loaded = False
        self.assertTrue(observe(api)["completed"])
        self.assertNotIn("exports", api.trace)

    def test_each_missing_required_export_skips_queries(self):
        for index in (0, 1, 3):
            api = Fake()
            values = list(api.found)
            values[index] = False
            api.found = tuple(values)
            result = observe(api)
            self.assertFalse(result["required_exports_complete"])
            self.assertNotIn("version", api.trace)
            self.assertNotIn("support", api.trace)

    def test_missing_version_export_does_not_invent_version_support(self):
        api = Fake()
        api.found = (True, True, False, True)
        result = observe(api)
        self.assertTrue(result["required_exports_complete"])
        self.assertFalse(result["version_query_attempted"])
        self.assertIsNone(result["major1_available"])
        self.assertIsNone(result["supported_minor"])
        self.assertIn("support", api.trace)

    def test_failed_hresult_discards_out_parameters(self):
        api = Fake()
        api.version_value = (-2147467259, 1, 999)
        api.support_value = (-2147467259, 999)
        result = observe(api)
        self.assertEqual(result["version_hresult"], 0x80004005)
        self.assertIsNone(result["major1_available"])
        self.assertIsNone(result["supported_minor"])
        self.assertIsNone(result["support_flags"])

    def test_cleanup_failure_discards_all_observations(self):
        api = Fake()
        api.clean = False
        result = observe(api)
        self.assertFalse(result["completed"])
        self.assertFalse(result["all_owned_resources_closed"])
        self.assertEqual(result["refusal_stage"], "resource_cleanup")
        self.assertNotIn("os_build", result)
        self.assertNotIn("token_is_elevated", result)

    def test_exception_text_never_leaves_fixed_failure(self):
        class Refusing(Fake):
            def os_version(self):
                raise OSError("PRIVATE_SENTINEL_DO_NOT_EMIT")

        result = observe(Refusing())
        self.assertEqual(result["refusal_stage"], "os_version")
        self.assertNotIn("PRIVATE_SENTINEL_DO_NOT_EMIT", json.dumps(result))
        self.assertTrue(result["all_owned_resources_closed"])

    def test_bad_scalar_facts_refuse(self):
        api = Fake()
        api.elevated = 2
        self.assertFalse(observe(api)["completed"])
        api = Fake()
        api.version_value = (0, 1, -1)
        self.assertFalse(observe(api)["completed"])
        api = Fake()
        api.support_value = (0, 1 << 64)
        self.assertFalse(observe(api)["completed"])
        api = Fake()
        api.found = (True, True, 1, True)
        self.assertFalse(observe(api)["completed"])


def main():
    if sys.argv[1:] == ["--self-test"]:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if sys.argv[1:] != ["--probe"]:
        print(json.dumps({**scope(), "refusal_stage": "selector"}))
        return 2
    allowed = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": "cisco-ai-defense/defenseclaw",
        "GITHUB_REF": "refs/heads/codex/axis-sandbox-feasibility",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    if not all(os.environ.get(key) == value for key, value in allowed.items()):
        print(json.dumps({**scope(), "refusal_stage": "host_scope"}))
        return 2
    result = observe(Native())
    raw = json.dumps(result, sort_keys=True, separators=(",", ":"))
    require(len(raw.encode("ascii")) <= 4096)
    print(raw)
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        print(json.dumps({**scope(), "refusal_stage": "serialization"}))
        code = 1
    raise SystemExit(code)
