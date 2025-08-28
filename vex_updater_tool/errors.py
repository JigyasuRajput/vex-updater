"""
Simple error classes for the VEX Updater Tool.
"""


class WorkflowError(Exception):
    """Error related to workflow operations."""
    
    def __init__(self, message: str, operation: str = None, recovery_steps: list = None):
        self.message = message
        self.operation = operation
        self.recovery_steps = recovery_steps or []
        super().__init__(self.message)


class ValidationError(Exception):
    """Error related to data validation."""
    
    def __init__(self, message: str, field: str = None, expected_values: list = None):
        self.message = message
        self.field = field
        self.expected_values = expected_values or []
        super().__init__(self.message)
