#!/usr/bin/env python3
import sys
import logging

# Set up logging to see detailed import errors
logging.basicConfig(level=logging.DEBUG)

# Try to import flask_limiter directly to see if it works
try:
    import flask_limiter
    print(f"Successfully imported flask_limiter {flask_limiter.__version__}")
except ImportError as e:
    print(f"Error importing flask_limiter: {e}")

# Try to run the Flask app
try:
    from flask.cli import main
    sys.exit(main())
except Exception as e:
    print(f"Error running Flask: {e}")
    import traceback
    traceback.print_exc()