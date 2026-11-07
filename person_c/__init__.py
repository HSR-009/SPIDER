# SPIDER Person C package
import sys

# Support both 'Person_c' and 'person_c' import paths uniformly
sys.modules.setdefault("person_c", sys.modules[__name__])
