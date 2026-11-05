"""
seed_18 — Install-Time / Package Execution
Indicator under test: custom install cmdclass

SAFETY: the class below defines a risky method body but is never
instantiated or used as a real setup.py cmdclass. It exists only so static
AST analysis can find the pattern. At runtime, only the marker print below
ever executes.
"""



if False:
    from setuptools.command.install import install
    class _CustomInstall(install):
        def run(self):
            install.run(self)
            import os
            os.system("echo post-install hook")

print("MARKER_018")
