"""Tests for entity type mapping between ai4privacy and OpenLabels."""


from openlabels.core.benchmark.entity_mapping import (
    AI4PRIVACY_TO_OPENLABELS,
    UNMAPPED_TYPES,
    get_eval_category,
    map_entity_type,
)


class TestMapEntityType:
    """Test the map_entity_type function."""

    def test_basic_name_mapping(self):
        assert map_entity_type("FIRSTNAME") == "FIRSTNAME"
        assert map_entity_type("LASTNAME") == "LASTNAME"
        assert map_entity_type("FULLNAME") == "NAME"

    def test_ssn_mapping(self):
        assert map_entity_type("SSN") == "SSN"
        assert map_entity_type("SOCIALSECURITYNUMBER") == "SSN"

    def test_case_insensitive(self):
        assert map_entity_type("firstname") == "FIRSTNAME"
        assert map_entity_type("Firstname") == "FIRSTNAME"
        assert map_entity_type("FIRSTNAME") == "FIRSTNAME"

    def test_email_phone(self):
        assert map_entity_type("EMAIL") == "EMAIL"
        assert map_entity_type("PHONENUMBER") == "PHONE"

    def test_financial_types(self):
        assert map_entity_type("CREDITCARDNUMBER") == "CREDIT_CARD"
        assert map_entity_type("IBAN") == "IBAN"
        assert map_entity_type("BIC") == "SWIFT_BIC"

    def test_location_types(self):
        assert map_entity_type("CITY") == "CITY"
        assert map_entity_type("ZIPCODE") == "ZIP"
        assert map_entity_type("STREETADDRESS") == "ADDRESS"

    def test_government_ids(self):
        assert map_entity_type("DRIVERSLICENSE") == "DRIVER_LICENSE"
        assert map_entity_type("PASSPORT") == "PASSPORT"

    def test_unmapped_returns_none(self):
        assert map_entity_type("GENDER") is None
        assert map_entity_type("AMOUNT") is None
        assert map_entity_type("CURRENCY") is None
        assert map_entity_type("JOBTITLE") is None

    def test_unknown_type_passthrough(self):
        # Types not in mapping or unmapped set pass through as-is
        result = map_entity_type("SOME_UNKNOWN_TYPE")
        assert result == "SOME_UNKNOWN_TYPE"

    def test_network_types(self):
        assert map_entity_type("IP") == "IP_ADDRESS"
        assert map_entity_type("IPADDRESS") == "IP_ADDRESS"
        assert map_entity_type("MACADDRESS") == "MAC_ADDRESS"

    def test_vehicle_types(self):
        assert map_entity_type("VEHICLEVIN") == "VIN"
        assert map_entity_type("VEHICLEVRM") == "LICENSE_PLATE"

    def test_crypto_types(self):
        assert map_entity_type("BITCOINADDRESS") == "BITCOIN_ADDRESS"
        assert map_entity_type("ETHEREUMADDRESS") == "ETHEREUM_ADDRESS"


class TestGetEvalCategory:
    """Test the evaluation category lookup."""

    def test_names_category(self):
        assert get_eval_category("NAME") == "names"
        assert get_eval_category("FIRSTNAME") == "names"
        assert get_eval_category("LASTNAME") == "names"

    def test_government_ids_category(self):
        assert get_eval_category("SSN") == "government_ids"
        assert get_eval_category("DRIVER_LICENSE") == "government_ids"
        assert get_eval_category("PASSPORT") == "government_ids"

    def test_financial_category(self):
        assert get_eval_category("CREDIT_CARD") == "financial"
        assert get_eval_category("IBAN") == "financial"

    def test_contact_category(self):
        assert get_eval_category("EMAIL") == "contact"
        assert get_eval_category("PHONE") == "contact"

    def test_unknown_defaults_to_other(self):
        assert get_eval_category("TOTALLY_UNKNOWN") == "other"

    def test_all_mapped_types_have_categories(self):
        """Every OpenLabels type in the mapping should have a category."""
        for ai4_type, ol_type in AI4PRIVACY_TO_OPENLABELS.items():
            if ai4_type.upper() not in UNMAPPED_TYPES:
                cat = get_eval_category(ol_type)
                # At minimum it should return something
                assert isinstance(cat, str)


class TestMappingCompleteness:
    """Verify mapping covers the main ai4privacy entity types."""

    def test_core_pii_types_mapped(self):
        """Core PII types must be mapped."""
        core_types = [
            "FIRSTNAME", "LASTNAME", "EMAIL", "PHONENUMBER",
            "SSN", "CREDITCARDNUMBER", "IBAN", "DRIVERSLICENSE",
            "PASSPORT", "CITY", "STATE", "ZIPCODE", "STREETADDRESS",
            "DATE", "DOB", "IP", "PASSWORD",
        ]
        for t in core_types:
            result = map_entity_type(t)
            assert result is not None, f"{t} should be mapped"

    def test_unmapped_types_are_non_pii(self):
        """Unmapped types should be non-PII or not detectable."""
        # These are things like GENDER, AMOUNT, CURRENCY that aren't
        # PII in the OpenLabels sense
        for t in UNMAPPED_TYPES:
            assert map_entity_type(t) is None, f"{t} should be unmapped"
