"""Domain exceptions with safe, operator-facing messages."""


class ImporterError(Exception):
    """Base class for expected importer failures."""


class AuthenticationError(ImporterError):
    """Authentication is absent or insufficient."""


class HiveMindAPIError(ImporterError):
    """The HiveMind CLI or API returned an unusable response."""


class ATIFSchemaError(ImporterError):
    """A trajectory cannot be mapped safely."""


class StateConflictError(ImporterError):
    """A stable source turn changed after it was imported."""


class StateStoreError(ImporterError):
    """The local SQLite import journal could not be used safely."""


class WeaveImportError(ImporterError):
    """The Weave SDK rejected or did not emit a turn."""


class HistoricalTurnConflictError(WeaveImportError):
    """A historical logical key already names different immutable content."""


class HistoricalTurnUncertainError(WeaveImportError):
    """A historical submission requires exact status reconciliation."""


class VerificationError(ImporterError):
    """Weave did not make an emitted turn durably visible."""


class BackfillError(ImporterError):
    """A sealed backfill plan could not be created or applied safely."""


class ReviewMirrorError(ImporterError):
    """The noncanonical review mirror could not proceed safely."""


class ReviewMirrorUncertainError(ReviewMirrorError):
    """A review root may have been emitted and requires exact reconciliation."""


class ReviewMirrorConflictError(ReviewMirrorError):
    """Review evidence has multiple or mismatched immutable matches."""
