#!/usr/bin/env python3
"""
Unit Tests for PayGuard Menu Bar - Optimized Version
Comprehensive test coverage for all components
"""

import pytest
import threading
import time
import tempfile
import os
import json
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import queue
import weakref
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from payguard_menubar_optimized import (
    PayGuardMenuBarOptimized, ScamDetector, NotificationManager, 
    PerformanceMonitor, AlertType, ScamPattern, DetectionResult
)

class TestScamPattern:
    """Test ScamPattern dataclass"""
    
    def test_pattern_initialization(self):
        """Test pattern initialization and regex compilation"""
        pattern = ScamPattern(r'\b1-\d{3}-\d{3}-\d{4}\b', 30, 'phone_number')
        
        assert pattern.pattern == r'\b1-\d{3}-\d{3}-\d{4}\b'
        assert pattern.weight == 30
        assert pattern.name == 'phone_number'
        assert hasattr(pattern, 'compiled_regex')
        assert pattern.compiled_regex.pattern == pattern.pattern
    
    def test_pattern_matching(self):
        """Test compiled regex matching"""
        pattern = ScamPattern(r'\b1-\d{3}-\d{3}-\d{4}\b', 30, 'phone_number')
        
        # Should match
        assert pattern.compiled_regex.search("Call 1-800-555-0199 now!")
        assert pattern.compiled_regex.search("Support: 1-888-123-4567")
        
        # Should not match
        assert not pattern.compiled_regex.search("Call 800-555-0199")
        assert not pattern.compiled_regex.search("Normal text")

class TestDetectionResult:
    """Test DetectionResult dataclass"""
    
    def test_detection_result_creation(self):
        """Test detection result creation"""
        result = DetectionResult(
            is_scam=True,
            confidence=85.5,
            alert_type=AlertType.PHONE_SCAM,
            patterns=['phone_number', 'urgency'],
            message="Scam detected",
            advice="Don't call",
            metadata={"score": 55}
        )
        
        assert result.is_scam is True
        assert result.confidence == 85.5
        assert result.alert_type == AlertType.PHONE_SCAM
        assert result.patterns == ['phone_number', 'urgency']
        assert result.message == "Scam detected"
        assert result.advice == "Don't call"
        assert result.metadata == {"score": 55}
    
    def test_detection_result_defaults(self):
        """Test detection result with defaults"""
        result = DetectionResult(is_scam=False)
        
        assert result.is_scam is False
        assert result.confidence == 0.0
        assert result.alert_type is None
        assert result.patterns == []
        assert result.message == ""
        assert result.advice == ""
        assert result.metadata == {}

class TestPerformanceMonitor:
    """Test PerformanceMonitor class"""
    
    @pytest.fixture
    def monitor(self):
        return PerformanceMonitor(max_samples=5)
    
    def test_initialization(self, monitor):
        """Test monitor initialization"""
        assert monitor.max_samples == 5
        assert monitor.screen_capture_times == []
        assert monitor.analysis_times == []
        assert monitor.clipboard_times == []
        assert hasattr(monitor, '_lock')
    
    def test_record_screen_capture_time(self, monitor):
        """Test recording screen capture times"""
        monitor.record_screen_capture_time(0.1)
        monitor.record_screen_capture_time(0.2)
        
        assert len(monitor.screen_capture_times) == 2
        assert monitor.screen_capture_times == [0.1, 0.2]
    
    def test_record_analysis_time(self, monitor):
        """Test recording analysis times"""
        monitor.record_analysis_time(0.05)
        monitor.record_analysis_time(0.08)
        
        assert len(monitor.analysis_times) == 2
        assert monitor.analysis_times == [0.05, 0.08]
    
    def test_record_clipboard_time(self, monitor):
        """Test recording clipboard times"""
        monitor.record_clipboard_time(0.01)
        monitor.record_clipboard_time(0.02)
        
        assert len(monitor.clipboard_times) == 2
        assert monitor.clipboard_times == [0.01, 0.02]
    
    def test_max_samples_limit(self, monitor):
        """Test that samples are limited to max_samples"""
        # Add more samples than max_samples
        for i in range(10):
            monitor.record_screen_capture_time(i * 0.1)
        
        assert len(monitor.screen_capture_times) == 5  # max_samples
        assert monitor.screen_capture_times == pytest.approx([0.5, 0.6, 0.7, 0.8, 0.9])  # Last 5
    
    def test_get_stats_empty(self, monitor):
        """Test stats with no data"""
        stats = monitor.get_stats()
        
        expected = {
            "screen_capture": {"avg": 0.0, "min": 0.0, "max": 0.0},
            "analysis": {"avg": 0.0, "min": 0.0, "max": 0.0},
            "clipboard": {"avg": 0.0, "min": 0.0, "max": 0.0}
        }
        
        assert stats == expected
    
    def test_get_stats_with_data(self, monitor):
        """Test stats calculation with data"""
        monitor.record_screen_capture_time(0.1)
        monitor.record_screen_capture_time(0.2)
        monitor.record_screen_capture_time(0.3)
        
        stats = monitor.get_stats()
        
        assert stats["screen_capture"]["avg"] == pytest.approx(0.2)
        assert stats["screen_capture"]["min"] == pytest.approx(0.1)
        assert stats["screen_capture"]["max"] == pytest.approx(0.3)
    
    def test_thread_safety(self, monitor):
        """Test thread safety of performance monitor"""
        def worker():
            for i in range(100):
                monitor.record_screen_capture_time(i * 0.001)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should have exactly max_samples entries
        assert len(monitor.screen_capture_times) == 5

class TestScamDetector:
    """Test ScamDetector class"""
    
    @pytest.fixture
    def detector(self):
        return ScamDetector()
    
    def test_initialization(self, detector):
        """Test detector initialization"""
        assert len(detector.patterns) > 0
        assert all(isinstance(p, ScamPattern) for p in detector.patterns)
        assert hasattr(detector, '_text_cache')
        assert hasattr(detector, '_cache_lock')
    
    def test_analyze_text_empty(self, detector):
        """Test analysis of empty/short text"""
        # Empty text
        result = detector.analyze_text("")
        assert result.is_scam is False
        
        # Short text
        result = detector.analyze_text("Hi")
        assert result.is_scam is False
        
        # Whitespace only
        result = detector.analyze_text("   ")
        assert result.is_scam is False
    
    def test_analyze_text_scam(self, detector):
        """Test analysis of scam text"""
        scam_text = "URGENT: Your computer is infected! Call 1-800-555-0199 immediately!"
        result = detector.analyze_text(scam_text)
        
        assert result.is_scam is True
        assert result.confidence > 70
        assert 'phone_number' in result.patterns
        assert 'urgency' in result.patterns
        assert 'virus_warning' in result.patterns
        assert result.alert_type is not None
        assert len(result.message) > 0
        assert len(result.advice) > 0
    
    def test_analyze_text_legitimate(self, detector):
        """Test analysis of legitimate text"""
        legitimate_texts = [
            "Welcome to our website. Please browse our products.",
            "Thank you for your purchase. Your order will arrive soon.",
            "Contact us for customer support at support@company.com"
        ]
        
        for text in legitimate_texts:
            result = detector.analyze_text(text)
            assert result.is_scam is False or result.confidence < 50
    
    def test_text_caching(self, detector):
        """Test text analysis caching"""
        text = "URGENT: Call 1-800-555-0199"
        
        # First analysis
        result1 = detector.analyze_text(text)
        
        # Second analysis should use cache
        result2 = detector.analyze_text(text)
        
        # Results should be identical
        assert result1.is_scam == result2.is_scam
        assert result1.confidence == result2.confidence
        assert result1.patterns == result2.patterns
    
    def test_pattern_detection_phone_number(self, detector):
        """Test phone number pattern detection"""
        texts_with_phones = [
            "Call 1-800-555-0199",
            "Support: 1-888-123-4567",
            "Contact 1-900-555-1234"
        ]
        
        for text in texts_with_phones:
            result = detector.analyze_text(text)
            assert 'phone_number' in result.patterns
    
    def test_pattern_detection_urgency(self, detector):
        """Test urgency pattern detection"""
        urgent_texts = [
            "URGENT action required",
            "Act now or lose access",
            "Immediate response needed",
            "Call now to avoid charges"
        ]
        
        for text in urgent_texts:
            result = detector.analyze_text(text)
            assert 'urgency' in result.patterns
    
    def test_pattern_detection_virus_warning(self, detector):
        """Test virus warning pattern detection"""
        virus_texts = [
            "Your computer is infected",
            "VIRUS DETECTED on your system",
            "Malware found in your files",
            "Trojan detected"
        ]
        
        for text in virus_texts:
            result = detector.analyze_text(text)
            assert 'virus_warning' in result.patterns
    
    @patch('payguard_menubar_optimized.PIL_AVAILABLE', False)
    def test_analyze_image_colors_no_pil(self, detector):
        """Test image analysis when PIL is not available"""
        result = detector.analyze_image_colors(b"fake_image_data")
        assert result.is_scam is False
    
    @patch('payguard_menubar_optimized.PIL_AVAILABLE', True)
    @patch('payguard_menubar_optimized.Image')
    def test_analyze_image_colors_red_alert(self, mock_image, detector):
        """Test red alert detection in images"""
        # Mock image with red colors
        mock_img = Mock()
        mock_img.size = (800, 600)
        mock_img.getcolors.return_value = [
            (1000, (255, 0, 0)),  # Red pixels
            (500, (255, 255, 255))  # White pixels
        ]
        
        mock_image.open.return_value = mock_img
        
        result = detector.analyze_image_colors(b"fake_image_data")
        
        assert result.is_scam is True
        assert result.alert_type == AlertType.VISUAL_RED_ALERT
        assert result.confidence > 80
        assert "FAKE SECURITY ALERT" in result.message
    
    @patch('payguard_menubar_optimized.PIL_AVAILABLE', True)
    @patch('payguard_menubar_optimized.Image')
    def test_analyze_image_colors_normal(self, mock_image, detector):
        """Test normal image analysis"""
        # Mock image with normal colors
        mock_img = Mock()
        mock_img.size = (800, 600)
        mock_img.getcolors.return_value = [
            (1000, (100, 150, 200)),  # Blue-ish pixels
            (500, (255, 255, 255))   # White pixels
        ]
        
        mock_image.open.return_value = mock_img
        
        result = detector.analyze_image_colors(b"fake_image_data")
        
        assert result.is_scam is False
    
    def test_determine_alert_type(self, detector):
        """Test alert type determination"""
        # Phone scam
        alert_type = detector._determine_alert_type(['phone_number', 'urgency'])
        assert alert_type == AlertType.PHONE_SCAM
        
        # Virus warning
        alert_type = detector._determine_alert_type(['virus_warning', 'urgency'])
        assert alert_type == AlertType.VIRUS_WARNING
        
        # Phishing
        alert_type = detector._determine_alert_type(['phishing', 'account_threat'])
        assert alert_type == AlertType.PHISHING
        
        # Unknown
        alert_type = detector._determine_alert_type(['unknown_pattern'])
        assert alert_type is None
    
    def test_generate_message(self, detector):
        """Test message generation"""
        # Tech support scam
        message = detector._generate_message(['phone_number', 'virus_warning'], True)
        assert "FAKE TECH SUPPORT SCAM" in message
        
        # Phishing
        message = detector._generate_message(['phishing'], True)
        assert "PHISHING ATTEMPT" in message
        
        # Virus warning
        message = detector._generate_message(['virus_warning'], True)
        assert "FAKE VIRUS WARNING" in message
        
        # Generic scam
        message = detector._generate_message(['urgency'], True)
        assert "SCAM CONTENT" in message
        
        # Not a scam
        message = detector._generate_message([], False)
        assert message == ""
    
    def test_generate_advice(self, detector):
        """Test advice generation"""
        # Phone number advice
        advice = detector._generate_advice(['phone_number'], True)
        assert "NEVER call random phone numbers" in advice
        
        # Phishing advice
        advice = detector._generate_advice(['phishing'], True)
        assert "Do not enter personal information" in advice
        
        # Virus warning advice
        advice = detector._generate_advice(['virus_warning'], True)
        assert "fake virus warning" in advice
        
        # Generic advice
        advice = detector._generate_advice(['urgency'], True)
        assert "Close this window" in advice
        
        # Not a scam
        advice = detector._generate_advice([], False)
        assert advice == ""

class TestNotificationManager:
    """Test NotificationManager class"""
    
    @pytest.fixture
    def notification_manager(self):
        manager = NotificationManager(cooldown_seconds=1)
        yield manager
        manager.shutdown()
    
    def test_initialization(self, notification_manager):
        """Test notification manager initialization"""
        assert notification_manager.cooldown_seconds == 1
        assert notification_manager.last_alert_time == 0
        assert hasattr(notification_manager, 'notification_queue')
        assert hasattr(notification_manager, 'executor')
    
    def test_notify_user_throttling(self, notification_manager):
        """Test notification throttling"""
        # First critical notification should succeed
        result1 = notification_manager.notify_user("Test", "Message", critical=True)
        assert result1 is True
        
        # Second critical notification should be throttled
        result2 = notification_manager.notify_user("Test", "Message", critical=True)
        assert result2 is False
        
        # Non-critical notifications should not be throttled
        result3 = notification_manager.notify_user("Test", "Message", critical=False)
        assert result3 is True
    
    def test_notify_user_after_cooldown(self, notification_manager):
        """Test notifications after cooldown period"""
        # First notification
        result1 = notification_manager.notify_user("Test", "Message", critical=True)
        assert result1 is True
        
        # Wait for cooldown
        time.sleep(1.1)
        
        # Second notification should succeed
        result2 = notification_manager.notify_user("Test", "Message", critical=True)
        assert result2 is True
    
    def test_sanitize_text(self, notification_manager):
        """Test text sanitization"""
        # Test quote escaping
        result = notification_manager._sanitize_text('Text with "quotes"')
        assert result == 'Text with \\"quotes\\"'
        
        # Test backslash escaping
        result = notification_manager._sanitize_text('Text with \\backslash')
        assert result == 'Text with \\\\backslash'
        
        # Test combined
        result = notification_manager._sanitize_text('Text with "quotes" and \\backslash')
        assert result == 'Text with \\"quotes\\" and \\\\backslash'
    
    @patch('subprocess.run')
    def test_send_normal_notification(self, mock_subprocess, notification_manager):
        """Test sending normal notifications"""
        mock_subprocess.return_value = Mock(returncode=0)
        
        notification_manager._send_normal_notification("Test Title", "Test Message")
        
        # Should call osascript
        mock_subprocess.assert_called_once()
        args = mock_subprocess.call_args[0][0]
        assert "osascript" in args
        assert "display notification" in args[2]
    
    @patch('subprocess.run')
    def test_send_critical_notification(self, mock_subprocess, notification_manager):
        """Test sending critical notifications"""
        mock_subprocess.return_value = Mock(returncode=0, stdout="")
        
        notification_manager._send_critical_notification("Test Title", "Test Message")
        
        # Should call multiple subprocess commands (sound, notification, dialog)
        assert mock_subprocess.call_count >= 2
    
    def test_shutdown(self, notification_manager):
        """Test graceful shutdown"""
        # Manager should be running initially
        assert notification_manager._running is True
        
        # Shutdown
        notification_manager.shutdown()
        
        # Should be stopped
        assert notification_manager._running is False

class TestPayGuardMenuBarOptimized:
    """Test PayGuardMenuBarOptimized class"""
    
    @pytest.fixture
    def payguard(self):
        config = {
            "alert_cooldown": 1,
            "screen_check_interval": 1,
            "clipboard_check_interval": 1,
            "status_update_interval": 5,
            "enable_performance_monitoring": True
        }
        guard = PayGuardMenuBarOptimized(config)
        yield guard
        guard.shutdown()
    
    def test_initialization(self, payguard):
        """Test PayGuard initialization"""
        assert payguard.running is True
        assert payguard.scam_count == 0
        assert payguard.last_clipboard_content == ""
        assert hasattr(payguard, 'detector')
        assert hasattr(payguard, 'notification_manager')
        assert hasattr(payguard, 'performance_monitor')
    
    def test_default_config(self):
        """Test default configuration"""
        payguard = PayGuardMenuBarOptimized()
        config = payguard.config
        
        assert config["alert_cooldown"] == 10
        assert config["screen_check_interval"] == 4
        assert config["clipboard_check_interval"] == 2
        assert config["status_update_interval"] == 30
        assert config["enable_performance_monitoring"] is True
        
        payguard.shutdown()
    
    def test_custom_config(self):
        """Test custom configuration"""
        custom_config = {
            "alert_cooldown": 5,
            "screen_check_interval": 2,
            "enable_performance_monitoring": False
        }
        
        payguard = PayGuardMenuBarOptimized(custom_config)
        
        assert payguard.config["alert_cooldown"] == 5
        assert payguard.config["screen_check_interval"] == 2
        assert payguard.config["enable_performance_monitoring"] is False
        
        payguard.shutdown()
    
    @patch('subprocess.run')
    def test_capture_screen_success(self, mock_subprocess, payguard):
        """Test successful screen capture"""
        # Mock successful screencapture
        mock_subprocess.return_value = Mock(returncode=0)
        
        # Mock file operations
        test_data = b"fake_image_data"
        
        with patch('tempfile.mkstemp') as mock_mkstemp, \
             patch('os.close'), \
             patch.object(Path, 'exists', return_value=True), \
             patch.object(Path, 'read_bytes', return_value=test_data), \
             patch.object(Path, 'unlink'):
            
            mock_mkstemp.return_value = (1, "/tmp/test.png")
            
            result = payguard.capture_screen()
            
            assert result == test_data
            mock_subprocess.assert_called_once()
    
    @patch('subprocess.run')
    def test_capture_screen_failure(self, mock_subprocess, payguard):
        """Test failed screen capture"""
        # Mock failed screencapture
        mock_subprocess.return_value = Mock(returncode=1)
        
        result = payguard.capture_screen()
        
        assert result is None
    
    def test_analyze_screen(self, payguard):
        """Test screen analysis"""
        # Mock image data
        test_data = b"fake_image_data"
        
        with patch.object(payguard.detector, 'analyze_image_colors') as mock_analyze:
            mock_result = DetectionResult(is_scam=True, confidence=85)
            mock_analyze.return_value = mock_result
            
            result = payguard.analyze_screen(test_data)
            
            assert result == mock_result
            mock_analyze.assert_called_once_with(test_data)
    
    @patch('subprocess.run')
    def test_check_clipboard_success(self, mock_subprocess, payguard):
        """Test successful clipboard check"""
        # Mock successful pbpaste
        mock_subprocess.return_value = Mock(
            returncode=0, 
            stdout="URGENT: Call 1-800-555-0199"
        )
        
        result = payguard.check_clipboard()
        
        assert isinstance(result, DetectionResult)
        assert result.is_scam is True  # Should detect scam in clipboard
    
    @patch('subprocess.run')
    def test_check_clipboard_same_content(self, mock_subprocess, payguard):
        """Test clipboard check with same content"""
        # Set previous content
        payguard.last_clipboard_content = "Same content"
        
        # Mock pbpaste returning same content
        mock_subprocess.return_value = Mock(
            returncode=0, 
            stdout="Same content"
        )
        
        result = payguard.check_clipboard()
        
        assert result.is_scam is False  # Should skip analysis
    
    @patch('subprocess.run')
    def test_check_clipboard_failure(self, mock_subprocess, payguard):
        """Test failed clipboard check"""
        # Mock failed pbpaste
        mock_subprocess.return_value = Mock(returncode=1)
        
        result = payguard.check_clipboard()
        
        assert result.is_scam is False
    
    def test_handle_detection_scam(self, payguard):
        """Test handling scam detection"""
        result = DetectionResult(
            is_scam=True,
            confidence=85,
            message="Scam detected",
            alert_type=AlertType.PHONE_SCAM
        )
        
        with patch.object(payguard.notification_manager, 'notify_user') as mock_notify:
            mock_notify.return_value = True
            
            payguard.handle_detection(result, "screen")
            
            assert payguard.scam_count == 1
            mock_notify.assert_called_once()
    
    def test_handle_detection_no_scam(self, payguard):
        """Test handling non-scam detection"""
        result = DetectionResult(is_scam=False)
        
        with patch.object(payguard.notification_manager, 'notify_user') as mock_notify:
            payguard.handle_detection(result, "screen")
            
            assert payguard.scam_count == 0
            mock_notify.assert_not_called()
    
    def test_temp_file_manager(self, payguard):
        """Test temporary file management"""
        with payguard._temp_file_manager(".test") as temp_path:
            assert temp_path.exists()
            assert temp_path in payguard.temp_files
            
            # Write some data
            temp_path.write_text("test data")
            assert temp_path.read_text() == "test data"
        
        # File should be cleaned up
        assert not temp_path.exists()
        assert temp_path not in payguard.temp_files
    
    def test_temp_file_manager_exception(self, payguard):
        """Test temp file manager handles exceptions"""
        try:
            with payguard._temp_file_manager(".test") as temp_path:
                assert temp_path.exists()
                raise ValueError("Test exception")
        except ValueError:
            pass
        
        # File should still be cleaned up
        assert not temp_path.exists()
    
    def test_shutdown(self, payguard):
        """Test graceful shutdown"""
        # Add a temp file
        with payguard._temp_file_manager(".test") as temp_path:
            temp_path.write_text("test")
            temp_file = temp_path
        
        # Shutdown
        payguard.shutdown()
        
        assert payguard.running is False
        assert len(payguard.temp_files) == 0

class TestIntegration:
    """Integration tests for PayGuard components"""
    
    def test_end_to_end_scam_detection(self):
        """Test complete scam detection workflow"""
        config = {
            "alert_cooldown": 0.1,
            "enable_performance_monitoring": True
        }
        
        payguard = PayGuardMenuBarOptimized(config)
        
        try:
            # Test text-based scam detection
            scam_text = "URGENT: Your computer is infected! Call 1-800-555-0199"
            result = payguard.detector.analyze_text(scam_text)
            
            assert result.is_scam is True
            assert result.confidence > 70
            assert 'phone_number' in result.patterns
            assert 'virus_warning' in result.patterns
            
            # Test handling the detection
            with patch.object(payguard.notification_manager, 'notify_user') as mock_notify:
                mock_notify.return_value = True
                payguard.handle_detection(result, "test")
                
                assert payguard.scam_count == 1
                mock_notify.assert_called_once()
        
        finally:
            payguard.shutdown()
    
    def test_performance_monitoring_integration(self):
        """Test performance monitoring integration"""
        config = {"enable_performance_monitoring": True}
        payguard = PayGuardMenuBarOptimized(config)
        
        try:
            # Simulate some operations
            with patch('subprocess.run') as mock_subprocess:
                mock_subprocess.return_value = Mock(returncode=0, stdout="test")
                
                # This should record performance metrics
                payguard.check_clipboard()
                
                # Check that metrics were recorded
                stats = payguard.performance_monitor.get_stats()
                assert stats["clipboard"]["avg"] > 0
        
        finally:
            payguard.shutdown()

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])