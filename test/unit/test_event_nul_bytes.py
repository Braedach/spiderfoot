

class TestNulBytesInEventData:
    """PostgreSQL cannot store a NUL (0x00): two events were lost in a live scan ("A string literal cannot contain
    NUL (0x00) characters"). They are removed where the event is created."""

    def _root(self):
        from spiderfoot import SpiderFootEvent
        return SpiderFootEvent("ROOT", "root", "", None)

    def test_nul_bytes_are_removed(self):
        from spiderfoot import SpiderFootEvent
        evt = SpiderFootEvent("RAW_RIR_DATA", "abc\x00def\x00", "sfp_test", self._root())
        assert evt.data == "abcdef"

    def test_the_hash_is_computed_from_the_cleaned_data(self):
        from spiderfoot import SpiderFootEvent
        root = self._root()
        a = SpiderFootEvent("RAW_RIR_DATA", "abc\x00def", "sfp_test", root)
        b = SpiderFootEvent("RAW_RIR_DATA", "abcdef", "sfp_test", root)
        assert a.data == b.data

    def test_data_that_is_only_nul_bytes_is_still_rejected_as_empty(self):
        import pytest
        from spiderfoot import SpiderFootEvent
        with pytest.raises(ValueError):
            SpiderFootEvent("RAW_RIR_DATA", "\x00\x00", "sfp_test", self._root())

    def test_ordinary_data_is_untouched(self):
        from spiderfoot import SpiderFootEvent
        evt = SpiderFootEvent("RAW_RIR_DATA", "line one\nline two\t{\"a\": 1}", "sfp_test", self._root())
        assert evt.data == "line one\nline two\t{\"a\": 1}"
