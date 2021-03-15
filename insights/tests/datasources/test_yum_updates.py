from insights.core.spec_factory import DatasourceProvider
from insights.specs.datasources.yum_updates import yum_updates


# Verify that the yum_updates broker correctly executes.
def test_yum_updates_runs_correctly():
    broker = {}
    result = yum_updates(broker)
    assert result is not None
    assert isinstance(result, DatasourceProvider)
