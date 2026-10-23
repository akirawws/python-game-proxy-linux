
from __future__ import annotations

import pytest

from app.detector.ewma import EWMADetector
from app.detector.scoring import Detector, Decision, ScoringScale
from app.detector.statistics import StatisticsDetector
from app.detector.thresholds import (
    ThresholdDetector,
    ThresholdResult,
    ThresholdRule,
)


class TestStatisticsDetector:
    def test_check_insufficient_history(self) -> None:
        det = StatisticsDetector()
        assert det.check(100.0) == (False, 0.0)

    def test_check_within_sigma_not_exceeded(self) -> None:
        det = StatisticsDetector(sigma_factor=3.0)
        for value in (10.0, 11.0, 12.0, 11.0, 10.0):
            det.add(value)
        exceeded, z_score = det.check(11.0)
        assert exceeded is False
        assert z_score >= 0.0

    def test_check_outlier_exceeded(self) -> None:
        det = StatisticsDetector(sigma_factor=3.0)
        for value in (10.0, 11.0, 12.0, 11.0, 10.0):
            det.add(value)
        exceeded, z_score = det.check(100.0)
        assert exceeded is True
        assert z_score > 0.0

    def test_check_zero_stdev_same_value(self) -> None:
        det = StatisticsDetector()
        for value in (5.0, 5.0, 5.0, 5.0, 5.0):
            det.add(value)
        exceeded, z_score = det.check(5.0)
        assert exceeded is False
        assert z_score == 0.0

    def test_check_zero_stdev_different_value(self) -> None:
        det = StatisticsDetector()
        for value in (5.0, 5.0, 5.0, 5.0, 5.0):
            det.add(value)
        exceeded, z_score = det.check(6.0)
        assert exceeded is True
        assert z_score == 1.0

    def test_median_mad_insufficient_history(self) -> None:
        det = StatisticsDetector()
        assert det.median_mad_check(100.0) == (False, 0.0)

    def test_median_mad_outlier_exceeded(self) -> None:
        det = StatisticsDetector()
        for value in (10.0, 11.0, 12.0, 11.0, 10.0):
            det.add(value)
        exceeded, score = det.median_mad_check(100.0, mad_factor=3.0)
        assert exceeded is True
        assert score > 0.0

    def test_median_mad_zero_mad_same_value(self) -> None:
        det = StatisticsDetector()
        for value in (7.0, 7.0, 7.0, 7.0, 7.0):
            det.add(value)
        exceeded, score = det.median_mad_check(7.0)
        assert exceeded is False
        assert score == 0.0

    def test_window_size_limits_history(self) -> None:
        det = StatisticsDetector(window_size=5)
        for value in (1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0):
            det.add(value)
                                                                            
        exceeded, _ = det.check(8.0)
        assert exceeded is False
        exceeded, _ = det.check(100.0)
        assert exceeded is True


class TestThresholdDetector:
    def test_default_rule_nothing_exceeded(self) -> None:
        det = ThresholdDetector()
        result = det.check(1000, 1000, 100, 1000, 100, 1000)
        assert result == ThresholdResult(exceeded=False, score=0, reasons=[])

    def test_pps_exceeded(self) -> None:
        det = ThresholdDetector(ThresholdRule(max_pps=50))
        result = det.check(100, 0, 0, 0, 0, 0)
        assert result.exceeded is True
        assert result.score == 3                  
        assert len(result.reasons) == 1
        assert "in_pps" in result.reasons[0]
        assert "50" in result.reasons[0]

    def test_bps_exceeded(self) -> None:
        det = ThresholdDetector(ThresholdRule(max_bps=50))
        result = det.check(0, 100, 0, 0, 0, 0)
        assert result.exceeded is True
        assert result.score == 3
        assert "in_bps" in result.reasons[0]

    def test_tcp_new_exceeded(self) -> None:
        det = ThresholdDetector(ThresholdRule(max_new_tcp_per_s=10))
        result = det.check(0, 0, 50, 0, 0, 0)
        assert result.exceeded is True
        assert result.score == 2              
        assert "tcp_new" in result.reasons[0]

    def test_udp_pps_exceeded(self) -> None:
        det = ThresholdDetector(ThresholdRule(max_udp_pps=10))
        result = det.check(0, 0, 0, 100, 0, 0)
        assert result.exceeded is True
        assert result.score == 2              
        assert "udp_pps" in result.reasons[0]

    def test_new_sources_exceeded(self) -> None:
        det = ThresholdDetector(ThresholdRule(max_new_sources=5))
        result = det.check(0, 0, 0, 0, 50, 0)
        assert result.exceeded is True
        assert result.score == 2                  
        assert "new_sources" in result.reasons[0]

    def test_connections_exceeded(self) -> None:
        det = ThresholdDetector(ThresholdRule(max_connections=5))
        result = det.check(0, 0, 0, 0, 0, 50)
        assert result.exceeded is True
        assert result.score == 2                      
        assert "connections" in result.reasons[0]

    def test_threshold_equal_not_exceeded(self) -> None:
        det = ThresholdDetector(ThresholdRule(max_pps=100))
        result = det.check(100, 0, 0, 0, 0, 0)
        assert result.exceeded is False
        assert result.score == 0

    def test_zero_max_disabled(self) -> None:
        det = ThresholdDetector(ThresholdRule(max_pps=0))
        result = det.check(999999, 0, 0, 0, 0, 0)
        assert result.exceeded is False
        assert result.score == 0

    def test_multiple_exceeds_combine_scores_and_reasons(self) -> None:
        rule = ThresholdRule(max_pps=50, max_new_tcp_per_s=10)
        det = ThresholdDetector(rule)
        result = det.check(100, 0, 50, 0, 0, 0)
        assert result.exceeded is True
        assert result.score == 3 + 2                               
        assert len(result.reasons) == 2

    def test_all_fields_exceeded(self) -> None:
        rule = ThresholdRule(
            max_pps=10,
            max_bps=10,
            max_new_tcp_per_s=1,
            max_udp_pps=10,
            max_new_sources=1,
            max_connections=1,
        )
        det = ThresholdDetector(rule)
        result = det.check(100, 100, 5, 100, 5, 5)
        assert result.exceeded is True
        assert result.score == 3 + 3 + 2 + 2 + 2 + 2      
        assert len(result.reasons) == 6


class TestEWMADetector:
    def test_check_no_baseline(self) -> None:
        det = EWMADetector()
        assert det.check(100.0) == (False, 0.0)

    def test_check_nonpositive_baseline(self) -> None:
        det = EWMADetector(min_baseline=1.0)
        det._baseline = 0.0                            
        assert det.check(100.0) == (False, 0.0)

    def test_update_initializes_baseline(self) -> None:
        det = EWMADetector(min_baseline=1.0)
        baseline = det.update(100.0)
        assert baseline == 100.0
        assert det._baseline == 100.0

    def test_update_enforces_min_baseline(self) -> None:
        det = EWMADetector(min_baseline=50.0)
        baseline = det.update(1.0)
        assert baseline == 50.0

    def test_update_applies_alpha_smoothing(self) -> None:
        det = EWMADetector(alpha=0.5)
        det.update(100.0)
        baseline = det.update(200.0)
        assert baseline == 150.0                     

    def test_update_is_attack_does_not_adapt(self) -> None:
        det = EWMADetector(alpha=0.5)
        det.update(100.0)
        det.update(1000.0, is_attack=True)
        assert det._baseline == 100.0

    def test_freeze_prevents_updates(self) -> None:
        det = EWMADetector(alpha=0.5)
        det.update(100.0)
        det.freeze()
        det.update(200.0)
        assert det._baseline == 100.0

    def test_unfreeze_allows_updates(self) -> None:
        det = EWMADetector(alpha=0.5)
        det.update(100.0)
        det.freeze()
        det.unfreeze()
        det.update(200.0)
        assert det._baseline == 150.0

    def test_check_ratio_exceeded(self) -> None:
        det = EWMADetector(deviation_factor=3.0, min_baseline=1.0)
        det.update(100.0)
        exceeded, ratio = det.check(400.0)
        assert exceeded is True
        assert ratio == 4.0

    def test_check_ratio_not_exceeded(self) -> None:
        det = EWMADetector(deviation_factor=3.0, min_baseline=1.0)
        det.update(100.0)
        exceeded, ratio = det.check(200.0)
        assert exceeded is False
        assert ratio == 2.0


class TestScoringScale:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0, "normal"),
            (1, "normal"),
            (2, "low"),
            (3, "low"),
            (4, "medium"),
            (5, "medium"),
            (6, "high"),
            (100, "high"),
        ],
    )
    def test_level(self, score: int, expected: str) -> None:
        assert ScoringScale.level(score) == expected


class TestDetector:
    def _make(
        self,
        server_id: int = 1,
        confirmation_count: int = 2,
        cooldown_seconds: int = 0,
        observation_mode: bool = True,
        rule: ThresholdRule | None = None,
    ) -> Detector:
        det = Detector(
            server_id=server_id,
            threshold_detector=ThresholdDetector(rule) if rule else None,
            confirmation_count=confirmation_count,
            cooldown_seconds=cooldown_seconds,
        )
        det.set_observation_mode(observation_mode)
        return det

    def test_normal_traffic(self) -> None:
        det = self._make(cooldown_seconds=0)
        decision = det.evaluate(10, 10, 1, 10, 1, 10, now=0.0)
        assert isinstance(decision, Decision)
        assert decision.server_id == 1
        assert decision.action == "none"
        assert decision.level == "normal"
        assert decision.score == 0
        assert decision.reasons == []
        assert decision.details == "норма"
        assert decision.ttl_seconds == 0

    def test_threshold_exceed_not_confirmed_yet(self) -> None:
        rule = ThresholdRule(max_pps=50)
        det = self._make(
            rule=rule,
            confirmation_count=2,
            cooldown_seconds=0,
        )
        d1 = det.evaluate(100, 0, 0, 0, 0, 0, now=0.0)
        assert d1.action == "none"
        assert d1.score == 3
        assert d1.level == "low"

    def test_confirmation_leads_to_alert_in_observation_mode(self) -> None:
        rule = ThresholdRule(max_pps=50)
        det = self._make(
            rule=rule,
            confirmation_count=2,
            cooldown_seconds=0,
            observation_mode=True,
        )
        det.evaluate(100, 0, 0, 0, 0, 0, now=0.0)
        decision = det.evaluate(100, 0, 0, 0, 0, 0, now=10.0)
        assert decision.action == "alert"
        assert decision.level == "low"
        assert decision.ttl_seconds == 0
        assert "in_pps" in decision.details

    def test_high_score_triggers_drop_in_block_mode(self) -> None:
        rule = ThresholdRule(max_pps=50, max_bps=50)
        det = self._make(
            rule=rule,
            confirmation_count=1,
            cooldown_seconds=0,
            observation_mode=False,
        )
        decision = det.evaluate(100, 100, 0, 0, 0, 0, now=0.0)
        assert decision.action == "drop"
        assert decision.level == "high"
        assert decision.score == 6
        assert decision.ttl_seconds == 300

    def test_medium_score_triggers_limit_in_block_mode(self) -> None:
                                   
        rule = ThresholdRule(max_pps=50, max_new_tcp_per_s=10)
        det = self._make(
            rule=rule,
            confirmation_count=1,
            cooldown_seconds=0,
            observation_mode=False,
        )
        decision = det.evaluate(100, 0, 50, 0, 0, 0, now=0.0)
        assert decision.action == "limit"
        assert decision.level == "medium"
        assert decision.score == 5
        assert decision.ttl_seconds == 120

    def test_low_score_triggers_alert_in_block_mode(self) -> None:
        rule = ThresholdRule(max_new_tcp_per_s=10)
        det = self._make(
            rule=rule,
            confirmation_count=1,
            cooldown_seconds=0,
            observation_mode=False,
        )
        decision = det.evaluate(0, 0, 50, 0, 0, 0, now=0.0)
        assert decision.action == "alert"
        assert decision.level == "low"
        assert decision.score == 2
        assert decision.ttl_seconds == 0

    def test_cooldown_blocks_repeat_action(self) -> None:
                                         
        rule = ThresholdRule(max_pps=50, max_bps=50)
        det = self._make(
            rule=rule,
            confirmation_count=1,
            cooldown_seconds=3600,
            observation_mode=False,
        )
                                                  
        d1 = det.evaluate(100, 100, 0, 0, 0, 0, now=3600.0)
        assert d1.action == "drop"
        assert d1.level == "high"
                                                
        d2 = det.evaluate(100, 100, 0, 0, 0, 0, now=3610.0)
        assert d2.action == "none"
        assert d2.score == 6

    def test_action_resumes_after_cooldown(self) -> None:
        rule = ThresholdRule(max_pps=50, max_bps=50)
        det = self._make(
            rule=rule,
            confirmation_count=1,
            cooldown_seconds=3600,
            observation_mode=False,
        )
        det.evaluate(100, 100, 0, 0, 0, 0, now=3600.0)
                                                              
        decision = det.evaluate(100, 100, 0, 0, 0, 0, now=7200.0)
        assert decision.action == "drop"

    def test_ewma_and_stat_deviations_add_score(self) -> None:
        det = self._make(
            confirmation_count=1,
            cooldown_seconds=0,
            observation_mode=True,
        )
                                                         
        for i in range(5):
            det.evaluate(100, 0, 0, 0, 0, 0, now=float(i))
                                                              
        decision = det.evaluate(400, 0, 0, 0, 0, 0, now=10.0)
        assert decision.score == 4
        assert decision.level == "medium"
        assert decision.action == "alert"
        assert any("ewma deviation" in r for r in decision.reasons)
        assert any("stat z-score" in r for r in decision.reasons)

    def test_set_observation_mode(self) -> None:
        det = self._make()
        det.set_observation_mode(False)
        assert det._observation_mode is False
        det.set_observation_mode(True)
        assert det._observation_mode is True
