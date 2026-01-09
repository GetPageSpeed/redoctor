"""Tests for configuration."""


from redoctor.config import Config, CheckerType, AccelerationMode, SeederType


class TestConfig:
    """Test configuration options."""

    def test_default(self):
        config = Config.default()
        assert config.timeout == 10.0
        assert config.checker == CheckerType.AUTO

    def test_quick(self):
        config = Config.quick()
        assert config.timeout == 1.0
        assert config.max_attack_length == 256

    def test_thorough(self):
        config = Config.thorough()
        assert config.timeout == 30.0
        assert config.max_attack_length == 8192

    def test_custom_config(self):
        config = Config(
            timeout=5.0,
            max_attack_length=1000,
            checker=CheckerType.FUZZ,
        )
        assert config.timeout == 5.0
        assert config.max_attack_length == 1000
        assert config.checker == CheckerType.FUZZ

    def test_random_seed(self):
        config = Config(random_seed=42)
        assert config.random_seed == 42


class TestCheckerType:
    """Test checker type enum."""

    def test_values(self):
        assert CheckerType.AUTO.value == "auto"
        assert CheckerType.AUTOMATON.value == "automaton"
        assert CheckerType.FUZZ.value == "fuzz"


class TestAccelerationMode:
    """Test acceleration mode enum."""

    def test_values(self):
        assert AccelerationMode.AUTO.value == "auto"
        assert AccelerationMode.ON.value == "on"
        assert AccelerationMode.OFF.value == "off"


class TestSeederType:
    """Test seeder type enum."""

    def test_values(self):
        assert SeederType.STATIC.value == "static"
        assert SeederType.DYNAMIC.value == "dynamic"
