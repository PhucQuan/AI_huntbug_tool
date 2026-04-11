import pytest
import asyncio
from unittest.mock import patch, MagicMock
from core.recon.subdomain import SubdomainEnumerator

class TestSubdomainEnum:
    
    @pytest.mark.asyncio
    async def test_deduplication(self):
        """Test kết quả từ nhiều tool được deduplicate đúng"""
        
        enum = SubdomainEnumerator("mock_db.sqlite")
        # Mocking subfinder, amass and assetfinder
        with patch.object(enum, 'run_subfinder', return_value=["api.example.com", "dev.example.com"]):
            with patch.object(enum, 'run_amass', return_value=["api.example.com", "staging.example.com"]):
                with patch.object(enum, 'run_assetfinder', return_value=[]):
                    # Mock DB init and add calls to avoid real DB execution
                    with patch.object(enum.db, 'init_db'):
                        with patch.object(enum.db, 'add_subdomains'):
                            result = await enum.enumerate_subdomains("example.com")
                            
        assert len(result) == 3  # unique count (api, dev, staging)
        assert "api.example.com" in result
        assert "staging.example.com" in result

    @pytest.mark.asyncio
    async def test_tool_not_installed(self):
        """Nếu tool không có → skip, không crash"""
        enum = SubdomainEnumerator("mock_db.sqlite")
        with patch.object(enum, '_run_command', return_value=[]):
             with patch.object(enum.db, 'init_db'):
                with patch.object(enum.db, 'add_subdomains'):
                    result = await enum.enumerate_subdomains("example.com")
        assert isinstance(result, list)  # Should return empty safely

    @pytest.mark.asyncio
    async def test_takeover_detection(self):
        """Test fingerprint matching cho subdomain takeover"""
        enum = SubdomainEnumerator("mock_db.sqlite")
        
        # Mock dns answer
        mock_answer = MagicMock()
        mock_answer.target = "target.github.io"
        
        with patch('dns.asyncresolver.Resolver.resolve', return_value=[mock_answer]):
            result = await enum.check_takeover("test.example.com")
            
        assert result["vulnerable"] == True
        assert result["service"] == "GitHub Pages"
