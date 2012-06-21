Feature: Verifying a signed XML document

  Scenario: The XML document is properly signed

    Given a signed XML document
    When I check it's validity
    Then it should pass
