import unittest

from app.model_router import (
    GEMMA_FAST_MODEL,
    GEMMA_STRATEGY_MODEL,
    get_model_profile,
    resolve_model_name,
    route_model,
)


class ModelRouterTests(unittest.TestCase):
    def test_resolves_gemma_aliases(self):
        self.assertEqual(resolve_model_name("gemma"), GEMMA_FAST_MODEL)
        self.assertEqual(resolve_model_name("gemma-31b"), GEMMA_STRATEGY_MODEL)

    def test_routes_strategy_prompts_to_larger_gemma(self):
        self.assertEqual(route_model("propose le plan d'attaque complet", "enumeration"), GEMMA_STRATEGY_MODEL)
        self.assertEqual(route_model("scan la cible", "recon"), GEMMA_FAST_MODEL)

    def test_gemma_profiles_enable_native_tool_calling(self):
        profile = get_model_profile(GEMMA_FAST_MODEL)

        self.assertTrue(profile.native_tool_calling)
        self.assertEqual(profile.thinking_level, "low")


if __name__ == "__main__":
    unittest.main()
